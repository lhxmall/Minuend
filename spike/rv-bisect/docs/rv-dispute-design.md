# rv_rollup 争议机制设计说明（给 Rust 新手看的版本）

> 状态：**spike 原型**，没有审计，没有接进正式的 Minuend rollup。
> 分支：`spike/rv-bisect`。相关文件都在 `spike/rv-bisect/` 下面。
> 写于 2026-10-31；同日更新：CBOND = 120 000、多付退款、烧毁部分永久锁定、客户端 `max_aa_responses`（第 4、5b、6.5、8 节）；真实引擎移植试点（7.2）；增量 witness 承诺 MNWIT1 提案（7.3，共识变更，只在 spike 分支）。

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
| referee（裁判） | `aa/rv_game_ref.oscript` → `js/mkref.js` 生成 `aa/rv_game_ref.aa` | 跑二分博弈本身：mids / pick / resolve，管超时。**不管钱**（只收手续费），结果回调给开局的 AA | 10 / **848** |
| `rv_rollup` | `aa/rv_rollup.oscript` → `js/mkrollup.js` 生成 `aa/rv_rollup.aa` | 管高度、保证金、开局、判欺诈、作废、最终确认、取回保证金。**所有钱都在这里** | 42 / **750** |

为什么把钱和博弈分开？因为 referee 只认「开局的那个 AA」的回调。别人自己去 referee 开的局，结果碰不到 rollup 的钱。

地址（devnet 部署出来的，都是由代码内容算出的 chash160）：
- rv_step：`7USF3LMWZF53XJGAM2SS2QIQSTHD3YNA`
- referee：`W7OQFFFU6446637YBHIA7B74L6X4ZO5B`（加了 open / resolve 多付退款后的新地址；旧的是 `Z5GRE6KB…`）
- rollup：`W4BAKM5O2QOOBYTUY3FPKAICE5SY35BP`（CBOND 120 000 + 多付退款 + 新 referee 地址；旧的是 `LPXCU745…`）

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
- 押 **OBOND = 200 000 bytes**。多付的部分退回：退 `付款 − OBOND − FEE`（退款要单独发一笔响应交易，FEE 付这笔交易费；多付不超过 FEE = 2000 时不退）。
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

挑战者发：`{ "open": <submit 的 unit id> }`，押 **CBOND = 120 000 bytes**。多付的部分**全额**退回（`付款 − CBOND`），因为这笔退款只是给 referee 转 GF 的那笔响应交易里多一个输出，不另花交易费。

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
resolve 交易本身 referee 留 **RK = 10 000**，多付的部分在同一笔响应交易里退给发 resolve 的人。

rollup 收到回调后：
- **operator 赢**：operator 得到 `CBOND − GF − FEE = 108 000`。
- **挑战者赢**：说明这个提交是欺诈，记 `f<sid> = 1`。挑战者拿回 `108 000`；如果他是**第一个**证明欺诈的，再加 `OBOND / 2 = 100 000`，一共 **208 000**。OBOND 的另一半（100 000）记到 `burned`，**永久锁在 AA 里，没有任何命令能取出**（真正的烧毁，见 5c）。
- 不管谁赢，`n<sid>` 减 1。

### 3.7 欺诈：作废 h..最新，重新赛跑

如果被判欺诈的提交**当前仍然有效**，rollup 设 `top = h − 1`。
这一下就把 h、h+1、……一直到原来的最高高度**全部作废**（因为它们都链在一个错误的根上）。
赛跑从 h 重新开始：任何人（包括诚实的 operator）可以重新提交高度 h。

注意：
- 同一个欺诈提交上可能有好几局。只有第一个赢的挑战者拿 OBOND/2；后面赢的只拿回自己的 108 000，`burned` 不再增加，`top` 也不会再变（devnet 6d 测过）。
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
| CBOND | **120 000** | rollup | 挑战者每局的保证金（2026-10-31 定）。operator 赢一局拿 108 000，在 MAXSTEPS 时也有约 2.2 倍余量（见 6.2） |
| GF | 10 000 | rollup / referee | 每局转给 referee，付它的回调交易 |
| FEE | 2 000 | rollup | 每次付款扣下，付 rollup 自己的响应交易费 |
| GB | 1 000 | referee | referee 回调时附带的 bytes（触发一个 AA 必须带付款），留在 rollup |
| MK | 2 000 | referee | 每次 mids / pick，referee 只留 2000，其余退回给走棋的人（见第 5 节） |
| RK | 10 000 | referee | resolve 时 referee 留下的部分，多付的退回（见 5b） |
| T | 3 600 秒 | referee | 每一步的超时 |
| WIN | 86 400 秒 | rollup | 挑战窗口（24 小时） |
| K | 16 | referee | 二分的叉数 |
| MAXSTEPS | 2^40 | rollup | 一个高度最多多少步（2026-10-31 定：保持 2^40，不降到 2^32） |

---

## 5. 一次「走棋退款」修复（攻击第 2 轮发现）

ocore 要求每个直接触发 AA 的交易至少带 `bounce_fees`（最少 10 000 bytes）。
旧版 referee 把这 10 000 全留下了，所以 operator 每走一步就白花 10 000 + 交易费。
博弈一深（> 6 轮，约 1.7e7 步），operator 答一局的成本就超过了它赢了能拿到的 88 000——**诚实 operator 会被骚扰到亏钱**。

修法：referee 只留 MK = 2000，`rf = 触发金额 − 2000` 退回给走棋的人。resolve 仍然留 10 000（每局只有一次）。
devnet 修完后：operator 每次 mids 净花 −3372（原来 −11 372），referee 每步净赚约 +1398。

## 5b. 多付退款（2026-10-31）

以前 submit 付超过 OBOND、open 付超过 CBOND，多出来的就留在 AA 里了。现在都退回给发送者：

| 交易 | 留下 | 退回 | 为什么这样分 |
|---|---|---|---|
| rollup submit | OBOND（+ 最多 FEE） | `付款 − OBOND − FEE`（> 0 时） | submit 本来没有响应交易，退款要单独一笔，FEE 付它的交易费（和 rollup 所有付款都扣 FEE 同一个规则）；多付 ≤ 2000 不值得退 |
| rollup open | CBOND | `付款 − CBOND` 全额 | 退款只是「给 referee 转 GF」那笔响应交易里多一个输出 |
| referee open（别人直接开局） | GF | `付款 − GF` 全额 | rollup 总是正好付 GF，所以 rollup 永远收不到退款（给 rollup 一笔不带 data 的付款会触发它、bounce 掉整条链） |
| referee mids / pick | MK = 2000 | `付款 − MK` | 第 5 节 |
| referee resolve | RK = 10 000 | `付款 − RK` | 和回调同一笔响应交易 |

被 bounce 的交易（比如付了 OBOND + 70 000 但高度不对）照 ocore 规则退回，只扣 bounce fee 10 000。
finalize / reclaim 的触发交易（至少 10 000，ocore 的 bounce_fees 下限）仍然全部留在 rollup，没做退款（见第 8 节）。

## 5c. 烧掉的那一半永久锁定（2026-10-31 决定）

欺诈时 operator 保证金的一半（OBOND/2 = 100 000）记进 `burned`，**永远留在 rollup AA 里，没有任何命令能把它取出来**——没有 treasury，也没有奖励池。
这就是真正的「烧毁」：钱还在 AA 地址上，但没有任何一条代码路径能花它。（sim 里测了 `withdraw` / `burn` / 对欺诈 sid 的 `reclaim` / `finalize` 都 bounce。）

为什么不给它一个出口：
- **交给 treasury**：就要有一个能提钱的 key，等于重新引入一个受信任的人（这个 key 被盗或作恶，整个设计的「无需信任」就没了）。
- **放进奖励池分给挑战者**：骗子可以用自己的马甲当挑战者，把这一半也赢回来。现在骗子最多只能用马甲拿回另一半（第一个赢家的 OBOND/2），被烧的这一半他永远拿不回来，所以每次欺诈至少亏 100 000。
任何出口都会二选一地带回「受信任的 key」或「骗子马甲回本的路」，所以不留出口。

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
能拿到：`CBOND − GF − FEE`，CBOND = 100 000 时 88 000，**现在 CBOND = 120 000，是 108 000**。

| 步数 | 轮数 R | 修复前成本 | 修复前余量（CBOND 100k） | 修复后成本 | 余量（CBOND 100k） | 余量（**CBOND 120k**） |
|---|---|---|---|---|---|---|
| 62 | 2 | 35 027 | +52 973 | 19 027 | +68 973 | **+88 973**（5.7 倍） |
| 1e6 | 5 | 70 367 | +17 633 | 30 367 | +57 633 | **+77 633**（3.6 倍） |
| 2^32 | 8 | 105 707 | **−17 707** | 41 707 | +46 293 | **+66 293**（2.6 倍） |
| 2^40 | 10 | 129 267 | **−41 267** | 49 267 | +38 733 | **+58 733**（2.2 倍） |

**决定（2026-10-31）**：CBOND = 120 000，MAXSTEPS 保持 2^40。给 tps fee 涨价留余地。
（设了 `max_aa_responses` 之后每笔触发交易多 24 bytes 的头部，10 轮多约 240，不影响结论。）

### 6.3 诚实挑战者的成本

2^40 步时大约：10 × (pick 900 + tps 224 + 2000) + 单步（10 000 + 3326 + 573）+ resolve 11 467 ≈ **56 600**。
赢了第一个能拿 208 000（其中 100 000 来自 operator 的保证金），净赚 OBOND/2 − GF − FEE = 88 000 减去上面的成本。

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
   举例（只是按公式算的示意值）：网络 tps = 1 时每笔触发约 1 900，tps = 3 时约 21 000。一局 10 轮如果碰上 tps = 3，operator 的预付会超过 108 000（这是不设 max_aa_responses、按 11 个单位预付算的；最终结算按真实响应数 1 + 1 = 2 个单位，约低 5 倍，见 6.5）。
3. 客户端（operator / 挑战者的程序）给每笔触发设 `max_aa_responses` = 实际的响应链长度，**预付**的 count_units 从 11 降到 2～3。
   **但实测（6.5）最终结算的 tps fee 不变**：ocore 结算时按 `1 + count_aa_responses`（真实响应数）算，跟 max_aa_responses 无关
   （`storage.updateTpsFees`）。所以它省的是预付款（多付的变成只能抵以后 tps fee 的余额），不是最终费用。之前写的「tps fee 降 4～5 倍」不对，已改正。
4. CBOND 120 000 的余量仍然是为 tps fee 涨价留的。

诊断脚本：`js/tpsdiag.js`（读一个 devnet 节点的 sqlite 副本，列出大额 tps fee、elapsed 分布和每个地址的余额）。

### 6.5 `max_aa_responses`：已在测试客户端实现，devnet 实测（2026-10-31）

`js/rolldevnet.js` 现在每笔触发都设 `max_aa_responses`（用 headless wallet 的 `sendMulti`，`NOMAXR=1` 关掉做对照）：

| 触发 | max_aa_responses | 实际响应数（hub sqlite 的 `count_aa_responses`） |
|---|---|---|
| rollup submit / finalize / reclaim | 1 | 1（19 / 12 / 7 笔全部） |
| referee mids / pick | 1 | 1（17 / 15） |
| rv_step（单步 memo） | 1 | 1（6） |
| referee 直接 open | 1 | 1 |
| rollup open | 2 | 2（rollup → referee）；2 笔故意 bounce 的是 1 |
| referee resolve | 2 | 2（referee → rollup 回调）；1 笔故意 bounce 的是 1 |

没有一笔超过上限，没有因为 `max_aa_responses exceeded` bounce；119 项检查全过。

同一套测试跑两次（run 6 设了，run 8 不设），101 笔触发交易：

| | 设 max_aa_responses（run 6） | 不设（run 8） |
|---|---|---|
| 预付 tps fee 合计 | **48 545** | **7 255 120** |
| 单笔预付最大 | 5 730 | 1 205 193（每个钱包的第一笔，见 6.4） |
| 单笔预付中位数 | 224 | 224 |
| **最终结算 tps fee 合计** | **25 328** | **25 306** |
| 结算：1 个响应的触发 / 2 个响应的触发 | 224 / 573 | 224 / 573 |
| 每笔交易大小 | +24 bytes（头部多一个字段） | — |

结论：
- **最终 tps 费用一样**（差 22 bytes 是时间抖动）。设 max_aa_responses 只是把预付从「按 11 个单位」降到「按 2～3 个单位」，devnet 上把预付合计降了约 150 倍（主要是首笔 120 万的预付没了）。
  多预付的钱不会丢，但只能抵这个地址以后的 tps fee，不能取出——对只发几笔就不用的挑战者地址，这部分基本等于白花。所以仍然建议设。
- **代价**：预付少了，安全余量也少了。见证人选父单元时会跳过「每单位预付 < 3 × 当前网络 tps fee」的单元（`parent_composer.filterParentsByTpsFeeAndReplace`，`min_parentable_tps_fee_multiplier` 默认 3）。
  run 6 的竞赛测试里两笔同时发的 submit 每单位只预付 1120，见证人那边当前费已经涨到 4422 / 7311 的门槛，这两笔**被跳过了 253 秒**才被收进来（之后没有别的交易被跳过）。不设 max_aa_responses 时自己算进去的 11 个单位把本地 tps 撑高，预付高出很多，不会碰到这个问题。
  主网上 tps 低、变化慢，一般不会这样；但 operator / 挑战者程序要做好「交易一时不稳定」的处理，挑战窗口和每步 1 小时的截止时间要留出余量，不能卡着最后几分钟发。
- 对照数据：`js/tpscmp.js`（读节点 sqlite 副本 + rolldevnet 的结果 json，按触发类型列预付 / 结算 / 响应数）。

---

## 7. 测试覆盖

| 测试 | 结果 | 说明 |
|---|---|---|
| `js/rolltest.js`（真实 ocore 求值器模拟） | **209 / 209** | 含 'refund' 组 7 个、新的 'overpay' 组 33 个（多付退款、常量、烧毁部分取不出） |
| `js/rolldevnet.js`（aa-testkit devnet，真实交易、bounce、付款） | **119 / 119**（设 max_aa_responses 和不设各跑一次都全过） | 第 6 节：operator 超时、挑战者超时、同一高度两局、欺诈作废 + 迟到回调 + reclaim；第 7 节（新）：submit / open / resolve / referee 直接 open 多付退款的真实输出 |
| 官方 riscv-tests（rv32ui 42 + rv32um 8，每一步都用链上 rv_step 复核） | **48 / 50** | 没过的 `ma_data`（非对齐访存）、`fence_i` 是故意不支持，会 TRAP |
| **和 sail-riscv 0.16 对拍**（`xval/`，2026-10-31） | **0 处真不一致** | riscv-tests 13 731 步 + 随机单步 12 000 例（20 850 个被测步，总共比较 764 850 步），每一步比 pc / 32 个寄存器 / 内存；被测步同时用 rv_step（真实 ocore）复核。见 7.1 |
| 更早的 rv_game 对抗测试 | 300 / 300 + 300 局随机对手 + devnet 27/27 | 见 `README.md` |

日志在机器 `/data/hark/logs/rv/`：`rolltest-r4.log`、`rolldevnet6.log`（设 max_aa_responses）、`rolldevnet8.log`（不设）（+ `.json`）、`tpscmp6.txt` / `tpscmp8.txt`。

### 7.1 和独立实现 sail-riscv 对拍（2026-10-31）

**为什么要做：** 以前判断 rv_step 对不对，参照只有我们自己写的 JS 参考实现（`js/ref.js`）+ 官方 riscv-tests。如果 JS 和 rv_step 犯了同一个错，就查不出来。所以找一个**别人写的、公认正确**的实现来逐步对比。

**用的是谁：sail-riscv 0.16。** 它是 RISC-V 国际基金会采用的「官方形式化模型」（用 Sail 语言写规范，自动生成 C++ 模拟器）。在机器上**从源码编译**成功（约 13 分钟），所以没用 Spike / rvemu。工具全放在 `/data/hark/spike-rv/xval/` 下，没装任何系统级的东西：
- Sail 编译器 0.20.3（官方预编译包）、CMake 3.31.6（官方二进制包）；
- m4 1.4.19（从源码编，GMP 的 configure 需要它，机器上没有）；
- GMP 6.3.0（sail-riscv 的 CMake 自己下载编译）。
另外也拿官方发布的 0.16 二进制跑了一遍，结果和自己编的完全一样。

**怎么配置 sail（`xval/mkconfig.py`）：** 从 `sail_riscv_sim --rv32 --print-default-config` 生成两份配置：
- `rv32im-strict.json`：只开 I + M（再加 Zicsr，机器模式处理 trap 需要）。内存只有 `[0, 64 MiB)`，和 rv_step 的 2^24 个字一样大，别的地址都不映射（CLINT、设备树挪走）。非对齐访存 → 异常。不开 Zifencei。
- `rv32im-relaxed.json`：同上，但允许非对齐访存、打开 Zifencei。用来展示 rv_step「故意 TRAP」的地方和普通 RV32IM 核的差别。

**怎么比（每一步都比）：**
1. 同一个 ELF 分别交给 sail 和 JS 参考实现跑。sail 输出逐条指令的轨迹（写了哪个寄存器、写了哪块内存、有没有异常），我们把它「重放」成一份影子状态。
2. 每执行一步就比：pc、32 个寄存器、两边写过的每个内存字（起点是同一个 ELF 镜像，所以只比写过的就等于比整块内存）。
3. 同一步再交给**链上 rv_step（真实 ocore 求值器）**，前根、后根必须和 JS 一样。这样 rv_step = JS = sail。
4. 只有一边 trap 的步要分类：属于 rv_step 文档里写明的选择（`ecall a7=93` 停机、`a7=63` 读输入、FENCE / FENCE.I / CSR / MRET / WFI / EBREAK / 非对齐 → TRAP）记为「规范选择」；其他都算 bug。rv_step 只有一个 TRAP 标记（pc=1，没有 mcause / mepc），所以两边都 trap 时只检查「都 trap 了，寄存器和内存都没被改」。

**测了什么：**
- `xval/xtests.js`：官方 riscv-tests（rv32ui 42 个 + rv32um 8 个）。
- `xval/xfuzz.js`：随机单步。每个用例是一个很小的 ELF：先用 62 条 lui/addi 把 31 个寄存器装成随机值或边界值，再放被测指令（pc 随机，也包括内存最后一个字），后面再跟一条随机指令，并在访存地址附近放好数据。覆盖 53 类：rv32im 每一条指令 + fence / fence.i / ecall（a7 = 93 / 63 / 其他）/ ebreak / CSR / mret·wfi·sret / 非法编码 / 完全随机的字。专门加了边界情况：写 x0、有符号溢出、除以 0、INT_MIN / −1、用寄存器移位 ≥ 32、跳到非对齐地址、符号扩展的 load、非对齐的 load / store、内存末尾、越界和回绕的地址。

**结果：**

| 测试 | 规模 | 结果 |
|---|---|---|
| riscv-tests，strict 配置，每步也用 rv_step 复核 | 50 个测试，13 731 步 | **0 不一致**。48 个以 ecall 停机结束（规范选择）；`ma_data`（非对齐 load）和 `fence_i` 两边**都** trap |
| riscv-tests，relaxed 配置 | 13 731 步 | 0 bug；只有预期的 2 处规范差异：sail 允许那次非对齐 load、把 fence.i 当空操作 |
| 随机单步，strict，种子 1，4 路并行，被测步用 rv_step 复核 | 12 000 例，20 850 个被测步（rv_step 跑了 20 906 次），总共比较 764 850 步 | **0 不一致** |
| 随机单步，relaxed，种子 2 | 4 000 例，6 943 个被测步 | 0 bug（只有规范差异） |
| 官方发布的 sail 二进制（核对自己编的） | riscv-tests + 2 000 例 | 0 bug，分类数字一模一样 |

边界情况在 strict 跑里出现的次数：写 x0 1 713、有符号溢出 106、除以 0 264、INT_MIN/−1 129、寄存器移位 ≥32 598、分支目标非对齐 675、跳转目标非对齐 205、符号扩展 load 485、非对齐 load 514 / store 341、内存末尾 274、地址越界 535、地址回绕 168。

**规范差异（都是故意的，不是 bug）：**

| 指令 / 情况 | sail | rv_step |
|---|---|---|
| `ecall`，a7 = 93 | 进异常（m-call） | 停机（pc = 2） |
| `ecall`，a7 = 63 | 进异常 | 读输入树的一个字 |
| FENCE | 空操作 | TRAP |
| FENCE.I（开了 Zifencei 时） | 空操作 | TRAP |
| CSR 指令、MRET、WFI、SRET | 执行 | TRAP |
| 非对齐 load / store（relaxed 配置） | 允许 | TRAP |

guest 用 `riscv32im-unknown-none-elf` 编译、不用这些指令就不受影响（和以前的结论一样）。

**这个对拍本身靠得住吗（`xval/mutants.sh`）：** 故意在 JS 参考实现的副本里埋 bug，并且关掉 rv_step 复核（`RVSTEP=0`），看**只靠和 sail 比**能不能抓到。埋了 11 个：sltiu 当成有符号比较、lh 不做符号扩展、remu 除以 0 返回 0、div 的 INT_MIN/−1 结果错、sra 当成逻辑右移、寄存器移位用 6 位、jalr 不清最低位、sb 的字节掩码错、bge 当成无符号、mulhsu 两个操作数对调、auipc 不加 pc——**全部抓到**（次数见 `xval/README.md`）。（把移位位数从 `& 31` 改成 `& 63` 在 JS 里其实没区别，因为 JS 的移位运算本来就只看低 5 位，所以不算。）

**结论：没有发现 rv_step 或 JS 参考实现的错误，两者都没改。** rv_step 仍是 ops 1850、地址 `7USF3LMWZF53XJGAM2SS2QIQSTHD3YNA`，所以 rollup 模拟和 devnet 不需要重跑。

**对拍时踩到的一个坑（是 sail 轨迹格式的事，不是 rv_step 的事）：** 取指就出错（比如跳到内存外面）时，sail 不打印这条指令那一行，异常信息会紧跟在上一条指令后面，看起来像上一条指令出错了。改成加 `--trace-step`（每步之间空一行）按块解析就对了。

怎么跑（机器上）：`cd /data/hark/spike-rv/xval/tree/xval && setsid nohup ./run-xval.sh > /data/hark/logs/rv/xval-run.out 2>&1 < /dev/null &`（全套约 20 分钟）。日志：`/data/hark/logs/rv/xval-*.log`、`xval-fuzz-strict-summary.json`、`xval-fuzz-relaxed-summary.json`、`xval-mutants*.log`。

---

### 7.2 真实引擎移植试点（2026-10-31）

目录 `guest-engine/`（guest）和 `engine-diff/`（对拍工具），详细表格见 `guest-engine/README.md`。

- **移植了什么**：从 fix/47-all @ 20326c0 原样复制（只改 `use` 行、HashMap→BTreeMap、去掉 serde/thiserror）：订单簿 `OrderBook`（价格-时间优先、每个 unit 最多一笔成交、自成交、撤销日志）、账户 `Account`（成交记账、风险快照、逐仓、现货保证金）、`apply_fill_pair`（taker 手续费、claw、mark 规则）、`Engine::place`（全部下单检查：client_seq、价格/数量上限、挂单数上限、tick、价格带、模式、只减仓、初始保证金含挂单占用、逐仓托管）和 `cancel`。资金费率市场的 mark 段落没移植（试点里不开这种市场）；deposit 只保留记账效果。
- **编译障碍调查**：没有浮点数；i128 能用但是软件实现（一次 `position_risk` 约 1.25 万步）；HashMap 换 BTreeMap 不影响结果（遍历的地方都与顺序无关，或者之后会排序）；bincode、快照、WAL、环境变量、DAG 都留在链下。**真正的问题是成本**：`apply_one` 每个 unit 之后都把整棵 witness 树重算一遍。
- **对拍**：`engine-diff` 直接链接真实引擎，用签名 unit 喂给 `Engine::ingest`，和移植版比较状态哈希 + 每个 unit 的事件（成交明细或拒绝原因）。随机 300 个种子 × 300 单：**300/300 完全一致**。真实引擎 ↔ 移植版 ↔ riscv32im guest（JS 模型）三方对拍 9 个批次（挂单深度 200/800，普通 + 压力场景，最多 1 832 个 unit）：**9/9 一致**。sail-riscv 抽查：**16 196 951 条指令，和 JS 模型完全相同**，结果内存和哈希一致。对移植版埋 13 个 bug，抓到 7 个（2 个在试点范围内等价，4 个是随机批次很少碰到的边界）。
- **每单步数**（一单 = 一个 unit）：挂单 200–400 张时 7.3–9.4 万步，800–1 000 张时 18.9–20.4 万步，约等于 **4.3 万 + 170 × 挂单数**（`place` 每次把所有挂单扫 5 遍）。
- **轮数和成本**（R = ceil(log16 步数)，operator 成本 = R × 3372 + 11 467）：10 单 R=5–6，100 单 R=6–7，1000 单 R=7，成本 2.83–3.51 万 bytes，赔付 108 000 至少还剩 6.95 万。单个 unit 的第 2 层博弈 R=5。
- **没算进去、但完整移植后会占大头的部分**：每个 unit 重算 witness 根，约每张挂单 5.7 个 sha256 块 ≈ 2 万步（挂单 200 张约 500 万步，1000 张约 2000 万步），是撮合本身的 100 倍。建议在继续移植前把 witness 承诺改成增量式（只更新被改动的叶子）——提案和实测见 7.3。

### 7.3 增量 witness 承诺 MNWIT1（提案，2026-10-31）

> **这是给真实引擎的共识变更提案**（改 `wit_root` 的定义，要升 `ASSERTION_VERSION`、重新部署所有读 witness 的 AA）。
> 这个 spike 只在 `spike/rv-bisect` 里实现和测量；**fix/47-all、main、PR #51 一行都没改**。

**问题。** 真实引擎的 `apply_one` 每个 unit 之后都调用 `wit_root(&state)`：把整个状态格式化成字符串叶子（`acct:` / `pos:` / `ord:` / `adr:` / `adrx:` / `dep:` / `obond:` / `band:` / `meta:` + 哨兵 `~:end`），**排序**，再整棵 Obyte merkle 重算；同时还把整份叶子列表存进 `wit_leaf_trace`。这是 O(状态) 的：试点测得每张挂单约 5.7 个 sha256 块，guest 里实测（下表 legacy 列）挂单 200 张时每个 unit **6.0M 步**，是撮合本身（7.2 万步）的 80 倍以上，并且随订单簿线性变大。

**思路。** 叶子字符串**一个字都不改**（AA 照样能解析），只换掉「把叶子组织成树」的方式：用**按 key 定位的紧凑稀疏 Merkle 树**（compact sparse Merkle tree）。每个叶子有一个由它的「身份」算出的固定 key，它在树里的位置只由 key 决定，跟别的叶子什么时候插入无关。一个 unit 只改了几个叶子，就只重算这几条路径。

#### 7.3.1 规格

| 项 | 定义 |
|---|---|
| 叶子字符串 | 与 `minuend_state::wit_leaves` 完全相同（`acct:{hex}:{collateral}:{perp}:{w}`、`pos:{hex}:{market}:{qty}:{entry}:{iso}:{bucket}`、`ord:{hex id}:{market}:{side}:{price}:{seq}:{remaining}:{hex acct}:{iso}:{margin_left}`、`adr:` `adrx:` `dep:` `obond:` `band:` `meta:` 同理）。**不再有** `~:end` 哨兵 |
| 身份前缀 kid | 叶子字符串的前 2 个字段（`tag:id`）；`pos:` 取前 3 个（`pos:{hex}:{market}`）。即 `acct:{hex}`、`pos:{hex}:{m}`、`ord:{hex 订单 id}`、`adr:{地址}`、`adrx:{hex}`、`dep:{base64 unit}`、`obond:{hex}`、`band:{m}`、`meta:{m}`。一个 kid 在任何时刻最多对应一个叶子（这些本来就是现有排序树里做「相邻叶子不存在证明」用的 key） |
| key | `key = sha256("~K1:" ‖ kid)`，32 字节；树里的路径 = key 的比特，**高位在前**（第 0 层看第 0 字节最高位） |
| 叶子哈希 | `L = sha256("~L1:" ‖ hex(key) ‖ ":" ‖ 叶子字符串)`（hex 小写 64 字符） |
| 内部节点 | `N = sha256("~N1:" ‖ b64(left) ‖ b64(right))`（b64 = 标准 base64，44 字符，和现有 Obyte merkle 一样是「字符串拼接再 sha256」，AA 里直接能算） |
| 空子树 | `EMPTY` = 32 个 0 字节（b64 `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`），它不是任何 sha256 的输出 |
| 形状（规范形） | 空子树 = `EMPTY`；**只含 1 个叶子的子树 = 这个叶子的 L**（叶子停在能把它和别人分开的最浅位置）；含 ≥2 个叶子的子树 = `N(左, 右)`（某一边可以是 `EMPTY`）。空树的根 = `EMPTY` |
| 域分离 | 前缀 `~K1:` / `~L1:` / `~N1:` 互不相同；旧树的叶子都以小写 tag 开头（哨兵是 `~:end`，第二个字符不同），旧树的节点输入以 base64 字符开头，所以新旧两种树的任何哈希输入都不会撞；`1` 是版本号 |
| 根 | `wit_root = b64(根)`，仍是 44 字符 base64，**字段类型不变** |

**确定性。** 规范形是「叶子集合」的纯函数：同一组 (key, 叶子) 不管按什么顺序插入、中间插过又删掉什么，根都一样。实现上删除叶子后要「塌缩」：一个内部节点如果只剩一个叶子孩子（另一边空），就用这个叶子替换掉自己，并一路向上检查。

**创世根。** `ChainState::new()`（保险账户 + BTC_USD 的 `band:` / `meta:`）的 MNWIT1 根是 `8q+ZwYDtXcypxizCpTw0YfUr/6XPNkvLSZYJVHlwirk=`（3 个叶子；对照：现行 `GENESIS_WIT_ROOT` = `eAvY8Srl…` 用同一工具复算一致）。

#### 7.3.2 增量更新（dirty-leaf tracking）

- 状态里多一个 `wit_dirty`：本 unit 碰过的账户 id、`(市场, 订单 id)`、市场 id。
- 来源（试点里的钩子，真实引擎照搬）：`StateJournal`（下单路径本来就为回滚记录了所有碰过的账户、市场标量和订单簿里碰过的订单——成功提交和回滚时都把它记进 dirty）、`account_mut`、撤单、入金。真实引擎还要加：清算/ADL、提现、PERP 余额、地址绑定（`adr:`/`adrx:`）、已用入金锚点（`dep:`）、预言机保证金（`obond:`）、参数变更/上架（`band:`/`meta:`）、资金费率结算（所有持仓人）。
- 每个 unit 结束时（不管 Applied 还是 Rejected，和现在每个 unit 一个 wit 根一样）：对每个 dirty key 从状态重新生成叶子 → 算 L → 如果和树里的一样就跳过，不一样就更新，叶子消失就删除（账户还要删掉已平仓的 `pos:`）→ 只沿着被标脏的路径重算节点。dirty 是「超集」也没关系（被回滚的改动重新生成出来和原来一样，不产生任何路径重算）。
- **安全网**：漏标一个 dirty key 会让增量根和真正的根不一致。所以测试/验证节点里要有「每个 unit 增量根 == 从头重建的根」的断言（本 spike 的 witfuzz 就是这个检查，下面的变异测试证明它能抓住漏标）。

#### 7.3.3 证明（给 AA 用）

- **存在证明**：给出叶子字符串 `l` 和兄弟列表 `s_{d-1} … s_0`（从叶子往上）。AA：`kid` = 取 `l` 的前 2/3 个字段 → `k = sha256("~K1:"+kid, 'hex')` → `h = sha256("~L1:"+k+":"+l)` → 对 `i = d-1 … 0`：key 的第 i 位（hex 第 `i/4` 个字符查表得 0–15，再取对应比特）为 0 时 `h = sha256("~N1:"+h+s_i)`，为 1 时 `h = sha256("~N1:"+s_i+h)` → 等于 `wit_root`。证明长度 d ≈ log2(叶子数) + 1～2（实测 2 000 张挂单时平均 ≈ 12，最大 ≈ 20）。
- **不存在证明**（替代现在的「排序相邻叶子夹住」+ `wit_count` / `counts_root` / 哨兵）：给出 key `k` 路径上的终点：要么是 `EMPTY`，要么是**另一个**叶子 `(k', l')`，且 `k'` 的前 d 位和 `k` 相同、`k' ≠ k`；再加兄弟列表折叠到根。规范形保证这个位置上的子树里只有这一个叶子（或没有），所以 `k` 不在树里。
- AA 侧需要确认 `sha256(x, 'hex')` 在 ocore 里可用（不可用的话 key 改成 base64，按 6 比特一个字符取位，规格其余不变）。

#### 7.3.4 映射到现有字段 / 共识变更清单

| 现有 | MNWIT1 下 |
|---|---|
| `wit_root`（checkpoint，44 字符 base64） | 同类型，值变成 MNWIT1 根 |
| `wit_trace` / `trace_root`（每个 unit 一个根，再 merkle） | 结构不变，元素换成每个 unit 的 MNWIT1 根 |
| `wit_count`、`counts_root`、`GENESIS_WIT_COUNT`、`WIT_MAX_SENTINEL` | 不存在证明不再需要它们：可以删掉，或 `wit_count` 留作信息字段（叶子数增量维护很便宜） |
| `GENESIS_WIT_ROOT` | 换成 `8q+ZwYDtXcypxizCpTw0YfUr/6XPNkvLSZYJVHlwirk=` |
| `wit_leaf_trace`（每个 unit 存整份叶子列表，O(状态) 内存） | 换成每个 unit 的「改动叶子 + 证明」，争议只需要这些 |
| 10 个读 witness 的 AA（`minuend_dispute*.aa`、`minuend_rollup.aa`、`minuend_vault.aa`）、`post_batch.js`、`script_helpers.js`、`minuend-settle` 的提现证明 | 存在 / 不存在证明换成 7.3.3 的格式 |
| `ASSERTION_VERSION` | +1，所有 AA 重新部署 |

#### 7.3.5 代码和测试（`guest-engine/src/wit.rs`、`engine-diff/src/smt_ref.rs`）

- guest（no_std + alloc）：`Wit` / `Smt`（数组 arena 上的二叉树，空闲表复用节点；叶子字符串写在栈上的固定缓冲里，不占堆）。`run_batch_wit` 每个 unit 后 `commit`，guest 把每个 unit 的根写到 `OUT+0x20000` 字（8 字一个），并在结尾用同一组叶子从头重建一遍做自检（`scratch_ok`）。编译开关：默认 = 增量；`nowit` = 不算 witness（7.2 的数字）；`legacywit` = 每个 unit 按现行规则（排序 + Obyte merkle + 哨兵）整棵重算，用来测对照成本。
- host 参考实现 `smt_ref`：**独立写的**、从头递归构造（对排好序的 key 二分），key 直接从叶子字符串里解析（就像 AA 那样），不共享 guest 的任何代码。叶子来自**真实引擎**的 `minuend_state::wit_leaves`（按试点建模的 tag 过滤：acct/pos/ord/band/meta）。
- 结果见下面「测试结果」和「步数」两张表。

**测试结果（2026-10-31，机器日志 `/data/hark/logs/rv/wit-*`，副本在 `guest-engine/results-2026-10-31/`）**

| 测试 | 结果 |
|---|---|
| 回归：真实引擎 vs 移植版 `fuzz 300 300`（加了 dirty 钩子之后） | **300/300** 一致（和 7.2 完全相同的事件统计） |
| 性质测试 `witfuzz 300 300 300`：300 个随机批次（一半压力场景），**每个 unit** 比较 ①真实引擎状态从头重建的根（smt_ref）②移植版增量根 ③移植版状态从头重建的根 | **300/300**，共 **112 794 个 unit** 三方全等；guest 末尾自检 `scratch_ok` 全 1 |
| 与插入历史无关：每个批次的最终叶子集合打乱顺序插入、中间插入又删除垃圾 key | **300/300** 根相同 |
| 纯树随机测试：300 轮随机 set/remove（含共享 253 位前缀的 key，测深层分裂/塌缩），每一步比增量根和从头重建 | **300/300**，34 894 步 |
| host 参考 vs guest（JS 模型）逐 unit 比根：7 个基准批次（深度 200/800/2000 × 10/100/1000 单） | 见下面步数表，**全部 roots_equal** |
| 上游 `#[test]` 场景回放（`engine-diff/scenarios/upstream.scn`，47 个批次，355 个 unit）：真实引擎 vs 移植版（哈希 + 事件 + 每个 unit 的根） | **47/47** |
| 同上 47 个批次过 riscv32im guest（JS 模型，`js/witscen.js`） | **47/47**（7 336 万步） |
| sail-riscv 抽查（`xval/witsail.js`，embed 构建，比较指令数 + 事件 + 全部 unit 根） | 场景 `bnd_fee_guard_equity_clause`（两个市场，9 个 unit）：**2 005 758 = 2 005 758** 条指令，111 个结果字全等；基准 `depth200 N=10`（236 个 unit）：**52 812 940 = 52 812 940**，2 154 个结果字（含 236 个根）全等，最终根 = host 参考 `cca129b2…978c`，状态哈希 = 真实引擎 |
| 变异测试（`guest-engine/scripts/wit-mut.sh`；每个变异体跑 `fuzz 100 300` + 场景回放 + `witfuzz 30 300`，任何一项不一致算抓到） | 移植版 13 个变异 **抓到 10 个**（7.2 时是 7 个）；witness 专用 6 个变异 **6/6** |

- 7.2 里剩下的 4 个「边界」变异：**3 个被场景回放抓到**——孤立仓位开仓 `equity − margin < im + resting` 改成 `<=`（场景：margin 恰好等于权益）；孤立仓位按比例释放保证金的取整（场景：100 USD 桶分 0.003 BTC 三次平）；taker 手续费保护的权益条件（需要**第二个市场**：孤立仓位爆仓平仓后现金 10 020 USD 但交叉权益只剩 20 USD，手续费 40 USD → 原代码拒绝；两边各放一个刚好 0 和刚好 = 手续费的对照场景）。第 4 个「从负余额对手方 claw」**是等价变异**：对手方余额为负时变异体算出负的 `pay`，被后面的 `if pay > 0` 挡掉，和原代码的 0 完全同效，任何输入都区分不出来。
- 另外 2 个仍存活的和 7.2 一样是试点范围内等价：mark ±10% 带（没有预言机指数时 mark 冻结，永远走不到）、`liquidatable`（下单路径不读）。
- witness 变异（去掉下单成功时的 journal 记脏、去掉 `account_mut` 钩子、去掉撤单钩子、`ord:` 叶子字段改错、删除时只在一侧塌缩、平仓后不删 `pos:` 叶子）：纯引擎对拍 `fuzz` 一个都抓不到（引擎状态没变），逐 unit 比根的检查全部抓到——这正是 7.3.2 说的「安全网」要做的事。

**每个 unit 的步数（JS 模型，只算下单流里的 unit；在同一次运行里读 unit 计数器被写的那一步，所以建簿和最后的哈希不计入）**

`inc` = 带 MNWIT1；`nowit` = 只撮合（7.2 的口径）；`wit` = inc − nowit；`legacy` = 现行规则（排序 + Obyte merkle）每个 unit 整棵重算的 witness 部分（只测了 N=10）。R = ceil(log16 步数)；operator 成本 = R × 3372 + 11 467，赔付 108 000。「单 unit R」= 第 2 层（只争一个 unit）用这批里最贵的那个 unit 算；「整批 R」= 整个下单流单层博弈。

| 订单簿 | N | 叶子 / 平均深度 / 最大深度 | inc 平均 / 中位 / 最大 | nowit | **wit** | legacy wit | 单 unit R（成本） | 整批步数 → R（成本） |
|---|---|---|---|---|---|---|---|---|
STEPS_ROWS_ZH

- witness 部分每个 unit **18–44 万步**，随订单簿只按 log 增长（深度 9→12）；现行整棵重算是 **600 万 / 2 230 万 / 5 500 万步**（挂单 200 / 800 / 2 000），**省 34× / 62× / 126×**，而且 legacy 还随挂单数线性涨。
- 成本：第 2 层单个 unit 的博弈 R = 5–6（2.83 万–3.17 万 bytes），现行规则下是 6–7；整批 1 000 单单层博弈 R = 8（3.84 万）。离 108 000 都还很远。R 是对数，所以链上成本只差一两轮；真正省的是**链下**：每个参与者算执行轨迹和每一步的内存 Merkle 根的工作量和步数成正比，少 1–2 个数量级。
- sha256 是大头（剖析：74% 的步数在 `compress256`，每块约 4.1k 步）。每改一个叶子 ≈ 1（key）+ 3～5（叶子）+ 2 × 深度 个块。还能再省的地方（没做）：没变的 `band:`/`meta:`（每次成交都被 journal 标脏）先比字段再决定要不要重算、缓存 key、4 叉节点（4 个 base64 孩子 = 180 字节正好 3 块，每两层省 1 块，约 −25%）。

## 8. 已知的缺口（诚实列出）

1. ~~多付的钱不退~~ 已修（5b）。剩下：finalize / reclaim 触发交易里的 10 000（bounce_fees 下限）仍全部留在 rollup；submit 多付 ≤ FEE 不退。
2. **烧掉的钱取不出来**：这是**有意的**（5c）：`burned` 永久锁定，不设 treasury 或奖励池。
3. **反复作废的代价只有 OBOND/2**：骗子可以用自己的马甲当「第一个挑战者」拿回一半保证金。所以每作废一次整条链（h..最新），骗子只亏 100 000 + 手续费。被连带作废的诚实 operator 要 reclaim 再重新提交，浪费时间。
4. **数据可用性（DA）没解决**：AA 读不到批次数据本身。挑战者拿不到输入数据就没法算根。「按块揭示」的 DA 挑战还没写。
5. **单批上限 2^40 步**（MAXSTEPS）。
6. **operator 和挑战者都不能是 AA**（`is_aa` 禁止）。用多签 AA 当 operator 的方案目前不行。
7. **挑战者必须在线**：单步阶段由挑战者举证；每步 1 小时内必须走。
8. ~~没和 sail-riscv 对拍~~ 已做（7.1）：sail-riscv 0.16，0 处真不一致。剩下：对拍只覆盖单步语义；trap 的具体种类（mcause 等）rv_step 不建模，只比「都 trap 了」。
9. **引擎只移植了一部分**（7.2）：下单/撤单/撮合/记账/保证金已经在 guest 里跑通并和真实引擎对拍一致；每个 unit 的 witness 根已按增量提案 MNWIT1 在 guest 里实现并逐 unit 对拍（7.3，**真实引擎还没改，是共识变更**）；强平/ADL、提现、预言机/资金费率、治理、commit-reveal 还没移植。
10. tps fee：测试客户端已设 `max_aa_responses`（6.5），只降预付、不降最终费用，并且预付少了交易可能暂时不被选作父单元；主网 tps 参数没核对。

---

## 9. 文件清单

- `aa/rv_step.oscript` / `.aa` —— 单步执行器
- `aa/rv_game_ref.oscript` / `.aa` + `js/mkref.js` —— referee
- `aa/rv_rollup.oscript` / `.aa` + `js/mkrollup.js` —— rollup
- `js/chain.js` —— 测试用的「多 AA 链」模拟（含 referee 退款）
- `js/rolltrace.js` —— 测试程序和它的诚实执行轨迹
- `js/rolltest.js` —— 求值器测试；`js/rolldevnet.js` —— devnet 测试
- `js/tpsdiag.js` —— tps fee 诊断
- `js/tpscmp.js` —— 按触发类型对比预付 / 结算 tps fee 和响应数
- `guest-engine/` —— 真实引擎移植试点（no_std guest，`rvengine`）；`engine-diff/` —— 真实引擎 vs 移植版对拍、批次生成、`witstat`；`js/pilotrun.js`、`pilotbench.js`、`pilotprof.js`、`xval/pilotsail.js`
- `guest-engine/src/wit.rs` —— 增量 witness 承诺 MNWIT1（7.3）；`engine-diff/src/smt_ref.rs` —— 独立的从头重建参考实现；`engine-diff` 子命令 `wroots` / `portroots` / `witfuzz` / `scen` / `genesis`；`engine-diff/scenarios/upstream.scn` —— 上游 `#[test]` 场景回放；`js/witrun.js`、`witbench.js`、`witscen.js`；`xval/witsail.js`；`guest-engine/scripts/wit-mut.sh`
- `xval/` —— 和 sail-riscv 对拍：`mkconfig.py`（生成 sail 配置）、`rv32im-strict.json` / `rv32im-relaxed.json`、`lib.js`（跑 sail、解析轨迹、写 ELF、逐步比较）、`xtests.js`（riscv-tests）、`xfuzz.js`（随机单步）、`mutants.sh`（埋 bug 自测）、`summarize.js`、`run-xval.sh`（全套）

怎么跑（在机器上）：

```sh
cd /data/hark/spike-rv/roll/js
OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore node rolltest.js
AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=$AATK/node_modules/ocore TESTDATA=<新目录> PORT=<空闲端口> OUT=<结果.json> node rolldevnet.js   # 加 NOMAXR=1 不设 max_aa_responses
NODE_PATH=$AATK/node_modules node tpscmp.js <节点 byteball.sqlite> <结果.json>
node tpsdiag.js <devnet 节点 byteball.sqlite 的副本>
```
