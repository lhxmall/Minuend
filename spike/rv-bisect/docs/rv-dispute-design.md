# rv_rollup 争议机制设计说明（给 Rust 新手看的版本）

> 状态：**spike 原型**，没有审计，没有接进正式的 Minuend rollup。
> 分支：`spike/rv-bisect`。相关文件都在 `spike/rv-bisect/` 下面。
> 写于 2026-10-31。

---

## 0. 一句话说明

operator（出块的人）每隔一段时间把「这一批交易执行完之后的状态」提交到链上，并押一笔保证金。
任何人觉得结果不对，都可以押保证金开一局「挑战博弈」。博弈用 **16 叉二分** 把双方的分歧一路缩小到 **一条 RISC-V 指令**，
最后由链上的单步执行器 `rv_step` 算出这一条指令的正确结果，谁错谁输。
24 小时内没人挑战（或者所有挑战都是 operator 赢），这一批就最终确认。

---

## 1. 三个 AA 分别干什么

AA（Autonomous Agent）是 Obyte 上的智能合约。这个原型用了三个：

| AA | 文件 | 作用 | 复杂度 / ops（真实 ocore 校验） |
|---|---|---|---|
| `rv_step` | `aa/rv_step.oscript` → `aa/rv_step.aa` | 执行**一条** rv32im 指令，把结果记成 `s_<前状态根> = 后状态根`。谁都能调，结果是确定的，相当于一个「纯函数缓存」 | 10 / **1850**（上限 100 / 2000） |
| referee（裁判） | `aa/rv_game_ref.oscript` → `js/mkref.js` 生成 `aa/rv_game_ref.aa` | 跑二分博弈本身：mids / pick / resolve，管超时。**不管钱**（只收手续费），结果回调给开局的 AA | 10 / **840** |
| `rv_rollup` | `aa/rv_rollup.oscript` → `js/mkrollup.js` 生成 `aa/rv_rollup.aa` | 管高度、保证金、开局、判欺诈、作废、最终确认、取回保证金。**所有钱都在这里** | 42 / **729** |

为什么把钱和博弈分开？因为 referee 只认「开局的那个 AA」的回调。别人自己去 referee 开的局，结果碰不到 rollup 的钱。

地址（devnet 部署出来的，都是由代码内容算出的 chash160）：
- rv_step：`7USF3LMWZF53XJGAM2SS2QIQSTHD3YNA`
- referee：`Z5GRE6KBBDMGYFSVHLSV5RBQVUOGI4CM`
- rollup：`LPXCU745RPWYWG6F3XFGVKE6Z6PG7FQ5`

---

## 2. 先理解「状态根」

整个机器（RISC-V 虚拟机）在某一时刻的状态，压缩成一个 44 字符的哈希：

```
state_root = sha256( pc ":" 32个寄存器用逗号连起来 ":" mem_root ":" inp_root ":" step )
```

- `pc`：程序计数器。`pc = 2` 表示程序正常结束（HALT），`pc = 1` 表示出错（TRAP）。
- `mem_root`：内存的 Merkle 根（2^24 个 32 位字）。
- `inp_root`：这一批的输入数据（交易）的 Merkle 根，只读。
- `step`：已经执行了多少步。

只要两个人对同一个 `state_root` 意见一致，就说明他们对整个机器状态意见一致。二分博弈就是在比较这些根。

---

## 3. 完整流程

### 3.1 提交（submit）：每个高度一场「赛跑」

operator 提交高度 h：

```json
{ "submit": h, "s0": ..., "steps": N, "final": ..., "inp": ..., "fpc": 2, "fregs": "...", "fmem": ..., "prev": ... }
```

规则（都在 `rv_rollup.oscript` 的 submit 分支里）：
- **只能提交下一个高度**：`h == top + 1`（`top` 是当前最高的有效高度）。所以每个高度同一时间只有一个有效提交——谁先提交谁占位，这就是「赛跑」（race）。
- 押 **OBOND = 200 000 bytes**。
- operator 不能是 AA（防止它故意让给自己的付款 bounce，把系统卡死）。
- `steps` 在 1 到 **2^40** 之间（`MAXSTEPS`）。
- `prev` 必须等于上一高度提交的 `final` 根（h=1 时是 `'genesis'`）。高度一个接一个地链起来。
- `final` 必须是一个已经停下来的状态（pc = 1 或 2）的哈希，而且 operator 要把这个状态的各部分（`fpc`、`fregs`、`fmem`）明文给出来，AA 自己重新算一遍哈希核对。`fmem` 存下来，作为下一高度的起始内存。

### 3.2 s0 绑定（起点不能乱写）

早期 spike 的一个大洞是：起点 `s0` 由 operator 随便写，写成一个没人知道原像的哈希，单步阶段就没人能提供「前状态」，operator 靠超时就赢了。

现在 `s0` **由 AA 自己算出来**，operator 只能照着填：

```
s0 = sha256( "0" ":" 32个0 ":" 上一高度的 fmem（h=1 用 GENMEM） ":" 本批 inp ":" "0" )
```

也就是：pc=0、寄存器全 0、step=0、内存 = 上一批结束时的内存、输入 = 这一批的输入根。
`GENMEM` 是程序镜像的内存根，部署时由 `mkrollup.js` 写死进 AA。

### 3.3 开局（open）：每个挑战者一局，可以同时开很多局

挑战者发：`{ "open": <submit 的 unit id> }`，押 **CBOND = 100 000 bytes**。

条件：这个提交仍然有效（是这个高度当前的赢家，且没被作废）、高度还没最终确认、还在 24 小时窗口内、挑战者不是 operator 本人、也不是 AA。

rollup 收到后：
- 记下这局 `G<open unit> = sid:挑战者:open`，这个提交的进行中局数 `n<sid>` 加 1。
- 把 **GF = 10 000 bytes** 转给 referee（付它最后回调那一笔交易的费用），并把 `s0`、`sN`(= final)、`n`(= steps)、防守方(operator)、挑战方 一起发给 referee 开局。

不同挑战者的局**互相独立、并行进行**。一个挑战者输了，不影响别的挑战者继续打。

### 3.4 16 叉二分：一路缩到一条指令

referee 里每局记录：`ref:防守方:挑战方:lo:hi:rlo:rhi:轮到谁:截止时间`。
意思是「双方都同意第 lo 步的根是 rlo，operator 声称第 hi 步的根是 rhi，挑战者不同意」。

一开始 `lo = 0, rlo = s0, hi = N, rhi = final`。

1. **mids（轮到 operator）**：在 (lo, hi) 之间取 15 个等分点，提交这 15 个点的状态根。
2. **pick（轮到挑战者）**：从 16 段里挑出**第一段**自己不同意的（这一段起点的根它同意，终点的根它不同意），区间缩小到原来的 1/16。
3. 重复，直到 `hi - lo == 1`，进入单步阶段（turn = `'s'`）。

每一步都有 **T = 3600 秒** 的截止时间。轮到谁、谁到时间没动，谁就输。

需要的轮数 R = ⌈log16(N)⌉：

| 步数 N | 轮数 R |
|---|---|
| 62（devnet 测试程序） | 2 |
| 1e6 | 5 |
| 2^32 | 8 |
| 2^40（MAXSTEPS） | 10 |

### 3.5 rv_step：链上执行那一条指令

到单步阶段，双方都同意第 lo 步的根 `rlo`，争的是第 lo+1 步的根。
**任何人**（一般是挑战者）调用 `rv_step`，提交 `rlo` 对应的完整前状态（pc、寄存器、内存根、输入根、step）和这一条指令需要的 Merkle 证明。
`rv_step` 执行这一条指令，写下 `s_<rlo> = 正确的后状态根`。

举证责任在挑战者：单步阶段到期还没人写 memo，就算 operator 赢。但 memo 只要在有人 resolve 之前写进去，晚一点也算数。

### 3.6 resolve：判输赢

任何人发 `{ "resolve": <局 id> }`：
- 单步阶段且 memo 已存在：memo == rhi → operator 赢（`'d'`），否则挑战者赢（`'c'`）。
- 否则如果过了截止时间：轮到谁走谁输。
- 都不是：bounce `'undecided'`。

referee 把结果和 **GB = 1000 bytes** 一起回调给 rollup：`{ res: 局 ref, w: 'd' 或 'c' }`。

rollup 收到回调后：
- **operator 赢**：operator 得到 `CBOND − GF − FEE = 88 000`。
- **挑战者赢**：说明这个提交是欺诈，记 `f<sid> = 1`。挑战者拿回 `88 000`；如果他是**第一个**证明欺诈的，再加 `OBOND / 2 = 100 000`，一共 **188 000**。OBOND 的另一半（100 000）记到 `burned`，留在 AA 里。
- 不管谁赢，`n<sid>` 减 1。

### 3.7 欺诈：作废 h..最新，重新赛跑

如果被判欺诈的提交**当前仍然有效**，rollup 设 `top = h − 1`。
这一下就把 h、h+1、……一直到原来的最高高度**全部作废**（因为它们都链在一个错误的根上）。
赛跑从 h 重新开始：任何人（包括诚实的 operator）可以重新提交高度 h。

注意：
- 同一个欺诈提交上可能有好几局。只有第一个赢的挑战者拿 OBOND/2；后面赢的只拿回自己的 88 000，`burned` 不再增加，`top` 也不会再变（devnet 6d 测过）。
- 被作废的高度上可能还有没打完的局，它们照常打完、照常付钱，但不会再影响 `top`。

### 3.8 finalize：24 小时后且没有进行中的局

任何人发 `{ "finalize": h }`。条件：
- 必须按顺序：`h == lf + 1`（`lf` 是最后一个已确认高度）。
- 提交仍有效、窗口（**WIN = 86 400 秒**）已过、`n<sid> == 0`（没有进行中的局）、没被判欺诈、`prev` 等于已确认的 h−1 的 final 根。

通过后 `lf = h`，operator 拿回 `OBOND − FEE = 198 000`。

### 3.9 reclaim：作废但不是欺诈的提交取回保证金

比如诚实的 h+1 因为 h 是欺诈被连带作废了。它的 operator 可以发 `{ "reclaim": sid }`。
条件：不再有效、没被判欺诈、没 finalize / reclaim 过、上面没有进行中的局。取回 `198 000`。

---

## 4. 常量

| 名字 | 值 | 在哪 | 意思 |
|---|---|---|---|
| OBOND | 200 000 | rollup | operator 每个高度的保证金 |
| CBOND | 100 000 | rollup | 挑战者每局的保证金。**建议改成 120 000，或者保持 100 000 但把 MAXSTEPS 降到 2^32**（见第 6 节） |
| GF | 10 000 | rollup / referee | 每局转给 referee，付它的回调交易 |
| FEE | 2 000 | rollup | 每次付款扣下，付 rollup 自己的响应交易费 |
| GB | 1 000 | referee | referee 回调时附带的 bytes（触发一个 AA 必须带付款），留在 rollup |
| MK | 2 000 | referee | 每次 mids / pick，referee 只留 2000，其余退回给走棋的人（见第 5 节） |
| T | 3 600 秒 | referee | 每一步的超时 |
| WIN | 86 400 秒 | rollup | 挑战窗口（24 小时） |
| K | 16 | referee | 二分的叉数 |
| MAXSTEPS | 2^40 | rollup | 一个高度最多多少步 |

---

## 5. 一次「走棋退款」修复（攻击第 2 轮发现）

ocore 要求每个直接触发 AA 的交易至少带 `bounce_fees`（最少 10 000 bytes）。
旧版 referee 把这 10 000 全留下了，所以 operator 每走一步就白花 10 000 + 交易费。
博弈一深（> 6 轮，约 1.7e7 步），operator 答一局的成本就超过了它赢了能拿到的 88 000——**诚实 operator 会被骚扰到亏钱**。

修法：referee 只留 MK = 2000，`rf = 触发金额 − 2000` 退回给走棋的人。resolve 仍然留 10 000（每局只有一次）。
devnet 修完后：operator 每次 mids 净花 −3372（原来 −11 372），referee 每步净赚约 +1398。

---

## 6. 成本表

### 6.1 实测每笔交易费（devnet，headers + payload，bytes）

| 操作 | 平均 / 最大 |
|---|---|
| submit | 1190 |
| open | 872 / 922 |
| mids | 1310 / 1556 |
| pick | 900 |
| step（rv_step） | 2791 / 3326 |
| resolve | 894 |

另外每笔还有 **tps fee**（按网络繁忙程度收的附加费）。devnet 上实际结算的是每笔 224～573。见第 6.4 节关于那个「120 万」的异常值。

### 6.2 operator 答一局的最坏成本 vs 能拿到的钱

operator 要走 R 次 mids（每次：留给 referee 的 2000 + 交易费 1556 + tps 224），
如果挑战者在某一步不动了，operator 再发一次 resolve（10 000 + 894 + 573）领钱。
能拿到：`CBOND − GF − FEE = 88 000`。

| 步数 | 轮数 R | 修复前成本 | 修复前余量 | 修复后成本 | 修复后余量 |
|---|---|---|---|---|---|
| 62 | 2 | 35 027 | +52 973 | 19 027 | +68 973 |
| 1e6 | 5 | 70 367 | +17 633 | 30 367 | +57 633 |
| 2^32 | 8 | 105 707 | **−17 707** | 41 707 | +46 293 |
| 2^40 | 10 | 129 267 | **−41 267** | 49 267 | +38 733 |

修复后，100 000 的 CBOND 在 2^40 时也有 1.79 倍余量。
**建议**：CBOND 改成 120 000（赢了拿 108 000，2^40 时 ≥ 2.2 倍），给 tps fee 涨价留余地；或者 CBOND 不变、MAXSTEPS 降到 2^32（2.1 倍）。

### 6.3 诚实挑战者的成本

2^40 步时大约：10 × (pick 900 + tps 224 + 2000) + 单步（10 000 + 3326 + 573）+ resolve 11 467 ≈ **56 600**。
赢了第一个能拿 188 000（其中 100 000 来自 operator 的保证金）。

### 6.4 那个 1 205 193 bytes 的 tps fee 是怎么回事

devnet 第 3 次和第 5 次运行里，有一笔 pick 显示 tps fee = 1 205 193。查了 devnet 的数据库（hub 节点的 `units` 和 `tps_fees_balances` 表）之后，结论是：

**这是 devnet 的假象，不是会在主网上累积的真实费用；也不是 timetravel 造成的。**

原理（ocore `parent_composer.getTpsFee` / `storage.getLocalTpsFee` / `composer.js`）：
- tps fee 是**预付款**。发交易时，钱包按「本地估计的 tps」预付：
  `每单位费 = round(tps_fee_multiplier × base_tps_fee × (e^(tps / tps_interval) − 1))`，
  再乘以 `count_units = 1 + 触发的 AA 数 × max_aa_responses`（不设 max_aa_responses 时默认 10，所以一笔 AA 触发算 **11** 个单位）。
- `tps = 计数 / elapsed`，`elapsed = 本交易时间戳 − 它的 last ball 的时间戳`，**为 0 时按 1 秒算**。
- 交易稳定后，ocore 按最终的 tps 算出「实际费」（`actual_tps_fee`），**多付的部分记到这个地址的 `tps_fees_balance`**，以后发交易时先从余额里扣。

devnet 上：3 个 witness 不停出块，交易几乎在同一秒就稳定，数据库里 1001 笔交易中 617 笔 elapsed = 0、331 笔 = 1。
devnet 参数 base 10、multiplier 10、tps_interval 2。一笔 AA 触发：计数 14（自己 11 + 另外 3 笔）、elapsed 0→1 秒，tps = 14：
`100 × (e^7 − 1) = 109 563`，`× 11 = 1 205 193`。和观测值完全一样。

所以**每个钱包地址第一次在 elapsed≈0 时发 AA 触发**，都要预付约 120 万；实际结算只有 224（或 573）。多出来的 1 204 969 变成这个地址的余额，之后每笔只补「估计 − 余额」= 224 左右。数据库里每个测试钱包的余额都停在 1 204 969 附近。
整个 run 5：1001 笔非 AA 交易预付 7 906 132，实际结算只有 135 293；差额全是这些「首笔预付」变成的余额（每个测试钱包约 120 万，3 个 witness 各约 18 万）。这笔钱没有被烧掉，但只能抵这个地址以后的 tps fee，不能取出来。第 3 次运行的数据一模一样（同样 9 笔、同样的金额）。
为什么出现在 pick 上：那个挑战者钱包第一笔交易（open）恰好在 timetravel 之后，elapsed = 84 601 秒，估计费是 0；第二笔（pick）才碰到 elapsed = 1，于是在 pick 上付了这笔预付款。timetravel 反而让估计费变成 0。

**对主网的含义（要记住的真东西）：**
1. 主网上交易的 last ball 一般比自己早得多，elapsed 不会是 0，所以不会出现这种 120 万的预付。
2. 但 tps fee 是**指数**增长的，而且一笔 AA 触发默认按 11 个单位收。主网初始参数是 tps_interval = 1（比 devnet 的 2 更陡；参数可以被投票改，当前值没核对）。
   举例（只是按公式算的示意值）：网络 tps = 1 时每笔触发约 1 900，tps = 3 时约 21 000。一局 10 轮如果碰上 tps = 3，operator 的成本会超过 88 000。
3. 所以：**客户端（operator / 挑战者的程序）应该给每笔触发设 `max_aa_responses` = 实际的响应链长度**。这样 count_units 从 11 降到 2～3，tps fee 降 4～5 倍。
   设小了会直接 bounce（ocore `aa_composer.js`：`max_aa_responses exceeded`），所以要按实际链长设：
   - mids / pick / submit / finalize / reclaim：1（只有一个 AA 响应；退款、付款都是给普通地址）
   - open：2（rollup → referee）
   - resolve：2（referee → rollup 回调）
   这是客户端设置，不用改 AA。原型里还没实现，也没在 devnet 上测。
4. 这也是建议 CBOND 留到 120 000 的理由之一。

诊断脚本：`js/tpsdiag.js`（读一个 devnet 节点的 sqlite 副本，列出大额 tps fee、elapsed 分布和每个地址的余额）。

---

## 7. 测试覆盖

| 测试 | 结果 | 说明 |
|---|---|---|
| `js/rolltest.js`（真实 ocore 求值器模拟） | **176 / 176** | 含 'refund' 组 7 个 |
| `js/rolldevnet.js`（aa-testkit devnet，真实交易、bounce、付款） | **104 / 104** | 第 6 节新增：operator 超时、挑战者超时、同一高度两局、欺诈作废 + 迟到回调 + reclaim |
| 官方 riscv-tests（rv32ui 42 + rv32um 8，每一步都用链上 rv_step 复核） | **48 / 50** | 没过的 `ma_data`（非对齐访存）、`fence_i` 是故意不支持，会 TRAP |
| 更早的 rv_game 对抗测试 | 300 / 300 + 300 局随机对手 + devnet 27/27 | 见 `README.md` |

日志在机器 `/data/hark/logs/rv/`：`rolltest-r3.log`、`rolldevnet5.log`（+ `.json`）。

---

## 8. 已知的缺口（诚实列出）

1. **多付的钱不退**：submit 付超过 OBOND、open 付超过 CBOND，多出来的留在 AA 里。
2. **烧掉的钱取不出来**：`burned`（每次欺诈 OBOND/2）留在 AA 里，没有 treasury，也没真正销毁。
3. **反复作废的代价只有 OBOND/2**：骗子可以用自己的马甲当「第一个挑战者」拿回一半保证金。所以每作废一次整条链（h..最新），骗子只亏 100 000 + 手续费。被连带作废的诚实 operator 要 reclaim 再重新提交，浪费时间。
4. **数据可用性（DA）没解决**：AA 读不到批次数据本身。挑战者拿不到输入数据就没法算根。「按块揭示」的 DA 挑战还没写。
5. **单批上限 2^40 步**（MAXSTEPS）。
6. **operator 和挑战者都不能是 AA**（`is_aa` 禁止）。用多签 AA 当 operator 的方案目前不行。
7. **挑战者必须在线**：单步阶段由挑战者举证；每步 1 小时内必须走。
8. **没和 sail-riscv（或其他独立实现）对拍**。参照只有自己的 JS 参考实现 + 官方 riscv-tests + 真实编译出的程序。
9. **引擎还没移植到 no_std**：真正的 Minuend 执行引擎还不能编译成 riscv32im guest，所以现在测的是测试程序，不是真实撮合。
10. tps fee：客户端还没设 `max_aa_responses`（见 6.4）；主网参数没核对。

---

## 9. 文件清单

- `aa/rv_step.oscript` / `.aa` —— 单步执行器
- `aa/rv_game_ref.oscript` / `.aa` + `js/mkref.js` —— referee
- `aa/rv_rollup.oscript` / `.aa` + `js/mkrollup.js` —— rollup
- `js/chain.js` —— 测试用的「多 AA 链」模拟（含 referee 退款）
- `js/rolltrace.js` —— 测试程序和它的诚实执行轨迹
- `js/rolltest.js` —— 求值器测试；`js/rolldevnet.js` —— devnet 测试
- `js/tpsdiag.js` —— tps fee 诊断

怎么跑（在机器上）：

```sh
cd /data/hark/spike-rv/roll/js
OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore node rolltest.js
AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=$AATK/node_modules/ocore TESTDATA=<新目录> PORT=<空闲端口> OUT=<结果.json> node rolldevnet.js
node tpsdiag.js <devnet 节点 byteball.sqlite 的副本>
```
