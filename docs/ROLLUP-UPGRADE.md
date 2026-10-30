# MINUEND 结算层：现在（纯永续）与以后升级

> 状态：**§2「现在」已实现**（三门 AA + 两个 dispute 谓词 + inbox；`CHAIN_ID=minuend-v2`）。
> 精确规则见 [MECHANISMS.md](MECHANISMS.md) §10–11。主网部署脚本
> `deploy_mainnet.js` 就绪，实发待助记词 + 审计。
> 本文记录：纯永续阶段把乐观结算做成什么样，以及以后若做成图灵完备侧链怎么升级。
> 现行实现有 rollup、两个 dispute AA 和 vault；付费否决已删。注意：§1 是旧版背景，
> §3 是未来提案、§6 是历史实施清单；§4 是当前约束、§5 是明确的非目标，均不是
> 当前可自动执行的升级流程。`{force}` 只钉时间戳，
> P-omit 目前恒 bounce `no fraud`，不能作为有效漏单挑战。

---

## 0. 一句话

- **现在（纯永续）：** 谁先稳定谁贴账；揭发必须指出算错的那一笔；主网用哈希 + 加减法当场核对；对不上才罚，对得上动不了真账。
- **以后（提案，尚未实现）：** 金库和提款树不动；换执行引擎、换裁判；若采用，用户需从旧金库按同一套证明提款后再存入新金库。没有自动迁移工具。

金库只认「已敲定的余额树」，不认永续、不知道成交、不参与升级。

---

## 1. 历史背景：移除旧付费否决

早期 v1 的 `challenge`（旧 `operp_vault.aa`）：已 lock、窗内、付 1000 GBYTE
即可立刻 `frozen=2`、清根、回滚高度；AA 不读数据包、不比对根、不要证明。
该付费否决已从当前 v2 移除；当前 `{challenge:1}` 在 rollup/vault 无对应 case。

旧设计的问题是诚实根也能被杀。交易所引擎（DAG、撮合、清算、PERP）没有这个问题——执行已经是确定性的。要重做的是 **贴到 Obyte 之后怎么敲定、怎么抓假账**。

引擎留下。结算层重做。

---

## 2. 现在：纯永续乐观结算

### 2.1 三类职责、三个 AA 实例（第一天就拆开）

Oscript 单次复杂度上限 100，现行金库已占约 76。共识不能再塞进托管。

| 门 | AA | 现在干什么 | 以后换什么 |
|---|---|---|---|
| 金库 | `minuend_vault.aa` | 充、提、只认 finalized 的 `aa_forest` | **几乎不改** |
| 记账 | `minuend_rollup.aa`（新） | 谁先稳定谁贴根、开窗、收判决 | 主张加 `version`，争议改派 |
| 裁判 | `minuend_dispute.aa` + `minuend_dispute_fill.aa` | 充提/漏单与成交谓词分别验证 | **两扇均可换掉** 或加新 case |

金库用 `var[ROLLUP_AA]['aa_forest_'||last_finalized]` 读根，自己不记候选、不挑战、不判刑。

没有 owner key、没有 `operators[]`、没有「只有原贴账人能应诉」。

### 2.2 贴批次（based，无许可）

任何人可发一笔 **组合单元**：`temp_data` + `{submit}`。poster 必须已有
`pool_<addr> >= 1e12`（1000 GBYTE）；submit 另付 10000 bytes bounce 费，
不是逐高度提交债。Obyte 上谁先稳定，这个高度就是谁的。已有未失败主张 → `height taken`。

链上主张只存这类字段（不存仓位、不成交）：

```
version = 1
height, prev, state_root, aa_forest,
trace_root, units_root, fills_root,
inbox_upto, da_unit = trigger.unit,
poster, submitted_at = timestamp
```

- 没有独立 `lock`。主网 AA 只被稳定单元触发，submit 到达时已经稳定。窗从 `submitted_at` 起算（`CHALLENGE_SECS`）。
- 没有 `OCCUPANCY_SECS` 替换诚实根。只有裁判判定欺诈，高度才重开。
- `state_root`（字节域）给节点重放、链 `prev`。AA 不验。
- `aa_forest`（hex 域）是 **提款权威**，叶子只承诺钱：`地址 + 抵押 + PERP + 已提`。仓位、挂单不进这棵树。

`temp_data` 里公开：本批 unit、每执行完一笔的 witness 根（≤512，约 32KB）、成交序列。链上只存 §2.2 所列的紧凑承诺根与状态字段，不存完整撮合状态。`TEMP_DATA_PURGE_TIMEOUT = 24h`，揭发时必须把那一笔和证明再交一遍，不能靠 `unit[]` 读已剥掉的 `data`。

### 2.3 主网怎么验（指到那一笔）

主网 **不重跑交易所**。AA 会的只有：sha256、加减乘除、`is_valid_merkle_proof`（复杂度 1）。

揭发者链下用 `Batch::validate_against` 定位第一处分歧，链上只核对他指的那一处。任一可用谓词成立 → 裁判通知记账：`{verdict:'fraud', h}`，主张作废、operator 常备池扣减、高度重开。不成立 → bounce，诚实根不动。

**没有应诉回合。** 贴账的人贴完可以下线。数据已在 L1。

| 谓词 | 证明什么 | 链上做什么 |
|---|---|---|
| P-trace | 第 k 笔的前后根属于 `trace_root`，unit k 属于 `units_root` | 三次 `is_valid_merkle_proof` |
| P-deposit | 充值后该账户抵押不是 +amount | 前后叶子 + 加法 |
| P-withdraw | 提款减法 / nonce 错 | 前后叶子 + 减法 |
| P-escrow | Cancel 退款与抵押变化不符 | 精确核对 post collateral = pre collateral + pre-order `margin_left`；Place escrow 无此分支 |
| P-fill-math | 这一笔成交的抵押/仓位/VWAP 算错 | 2 个账户叶 + 1 个挂单叶 + 算术 |
| P-ghost | 成交打在前状态不存在的挂单上 | 挂单成员证明失败即成立 |
| P-skip | 有更优价时序的活单没吃 | 出示那张更好的活单叶子，比价、比 seq |
| P-omit（禁用） | 设计目标：证明 inbox 中的 unit 未纳入本批 | 当前无可用证明；`force` 只钉时间戳、不能证明 unit 存在，该 case 恒 bounce `no fraud` |

P-skip 替代「在 AA 里重放订单簿」：不必证明「这是最优」，只要证明「存在更优却没成交」。

仓位和挂单放在 **witness 树**（`trace[k]`），不放进提款用的 `aa_forest`。两棵树由同一状态派生，绑在同一主张上：一处假，整高失败。

举例（P-fill-math）：在可验证的普通成交分支中，第 17 笔后 collateral 若应为 480、提交为 500，可用账户/订单证明核对恒等式。不等才构成欺诈；但任何负的预期 collateral 会直接 bounce `no fraud`，ADL kind-2 成交也没有该链上证明分支，不能声称可用此谓词证明。

### 2.4 inbox（记录入口；当前不能证明漏单）

用户可给记账 AA：`{force:1, unit_id}`，inbox 只记录时间戳。该触发不证明
`unit_id` 曾存在，因此当前 P-omit 恒 bounce `no fraud`；这还不是可用的抗审查漏单证明。

当前主张仍记录 `inbox_upto`，但不能据此断言所有时间戳较早的 inbox id 已有可验证存在性；P-omit 的重新启用需先设计该存在性证明。

### 2.5 常备池（资本门槛，不是逐高度债券或许可名单）

| | 当前规则 |
|---|---|
| 提交资格 | `{pool:1}` 为 poster 累积常备池；提交前须 `pool >= 1e12`，无逐高度 submit bond |
| 提交费用 | submit 支付 10000 bytes bounce 费；finalize 不退还所谓提交债 |
| 假揭发 | 谓词不成立即 bounce `no fraud`，**不能冻结诚实根** |
| 成功揭发 | rollup 从 operator 常备池扣 min(5e11, pool)，记入 challenger 的 `slash_reward`（债务上界=实际罚没），高度钉住待重提 |
| 取回资金 | `{claim:'pool'}` 仅在 `last_submitted == last_finalized` 且顶高度未失败时可取常备池 |
| 名单 | 无 |

旧版「付 1000 G 即可杀根」与逐高度提交债均非当前机制。

### 2.6 生命周期（高度 h）

```
任何人：先使自己的常备池达到 1e12，再提交组合单元 + 10000 bytes 费用
  → 已有未失败主张？bounce height taken
  → 写下根，3600 秒挑战窗开始（不锁逐高度债券）

窗内任何人：打裁判，带一条谓词
  → bounce：账不动
  → fraud：operator 常备池扣减（min(5e11, pool)），主张清掉，h 钉住待重提

窗后任何人：{finalize} → last_finalized=h（无提交债退款）
             金库从此对该 aa_forest 付款

7 天无进展：{escape_finalize} 仍在，任意人，不越过未结欺诈
链空闲（且顶高度未失败）后 poster 才可 `{claim:'pool'}` 取回常备池
```

### 2.7 temp_data framing 的滚动升级与回滚

新 producer 保持旧 watcher 可读：包内帧以 LF 分隔；首包无前缀，后续每个包
以 LF 开头；所有包都没有尾 LF。因此旧 watcher 的 `split("\\n")` 不会得到
尾部空 JSON frame。新 watcher 读取旧 producer 时，先对按顺序拼接的原始
gunzip package 字节校验 `data_root`，再仅在解析副本中补上旧多包缺失的边界 LF。
`data_root` 永远不对规范化后的文本计算；inline 单包也校验其原始字节 root。

这两个方向均可滚动：watcher 可先升级，也可先升级 producer；没有 framing-version
或强制 producer-first 停机顺序。回滚 watcher 到旧版后，新 producer 的包仍可读，
但旧 watcher 原本就不能正确解析「旧 producer 无包间分隔符」的多包批次；回滚会
失去新 reader 的这项旧批次兼容。不要重打已发布 package 或修改其 `data_root`。
曾经采用“每包尾部加 LF”的中间格式不能发给旧 watcher，因为 `split("\\n")`
会产生空尾帧；新 watcher 可读取它，但不应将其作为发布格式。

---

## 3. 以后：升到图灵完备侧链

「指到那一笔、那个账户」依赖死公式（充值 = 旧 + 金额，成交 = 旧 ± 盈亏）。任意合约没有这种公式，主网算不出「该是多少」，账户级一枪验算就断了。

乐观验证还能用，但「一步」从「一笔成交」变成「一条 VM 指令」：贴账的人承诺指令级（或可二分的）内存根；揭发先对到那一笔，再对到那一条指令；主网只验读格子、加减、写回。这是 Arbitrum / Cannon 那一套。工程量大，需要内存也是树的小虚拟机，不是在现在的 CLOB 引擎上打补丁。

Obyte 单次复杂度仍是 100：验一条指令做得到，验整段程序做不到。图灵完备阶段通常要 **多轮二分**（找到那一条指令），并允许 **任何人代打** 防守，不能绑原贴账人。

**现在不要做 WASM/MIPS。** 纯永续用账户级谓词更简单，揭发也不依赖对方在线。

### 3.1 升级时换什么、不换什么

| | 现在（version=1，纯永续） | 以后（version=2，任意合约） |
|---|---|---|
| 执行 | 现有永续引擎 | 新 VM，新 crate，不是改 CLOB |
| 金库 | 认 `aa_forest` 提款 | 新金库同样只认余额树；旧金库仍能提 |
| 记账 | version=1 + 当前结算承诺根集合 | version=2，争议改派新裁判 |
| 裁判 | P-deposit / P-fill-math / P-skip / P-omit | 换成单指令验证 |
| 提款叶子 | `地址 + 抵押 + PERP + 已提` | 仍是「地址 → 钱」，不加仓位、不加合约存储 |

### 3.2 升级步骤（无管理员一键切）

无 owner。没有原地升级或自动迁移；若部署新 AA，用户需从旧部署按 finalized-root
证明提款，再自行存入新部署。这是可行的用户操作路径，不是内置升级工具。

1. 部署新裁判（和如需要的新记账 / 新金库）。
2. 旧链停在某个高度：不再接受 `submit`，或只许把已过窗的主张 `finalize`。
3. 用户用 **已经 finalize 的证明** 从旧金库提出来，存进新金库（同一套 Merkle 提款）。
4. 新侧链创世 = 旧余额快照，或用户自己再充。

可另做迁移辅助：用户签一次，旧金库付给新金库并在新树记同一余额——仍是用户授权，不是后门。

旧高度永远能按旧规则提。不要在旧 AA 里「热切换」裁判逻辑（复杂度、审计、已锁定主张会对不上）。

### 3.3 主张带版本，别带业务

`version` 决定争议交给哪扇裁判。金库永远只读 `aa_forest`，不读 `version` 的业务含义。

以后加现货、加合约，都是新裁判 + 可选新记账，不是给金库加 `if`。

---

## 4. 去不掉的下限

| 层 | 为什么还在 |
|---|---|
| Obyte 约 12 个 Order Provider | L1 排序；主张等稳定。基于它做「谁先稳定谁贴」 |
| 常备池 | `pool_<addr> >= 1e12` 是提交资本门槛；不是逐高度债券，也不是地址名单 |
| `temp_data` 24h 后删正文 | 揭发必须自带那一笔 |
| 复杂度 100 | 主网验不了整批撮合 / 整段程序，只能验谓词或单指令 |

---

## 5. 明确不做

- 继续「付钱即处决」
- 委员会签根、指定 operator、只有原 poster 应诉
- 链下 DA（IPFS 当数据可用性）
- 把争议塞回现行 `minuend_vault.aa`
- 把仓位 / 挂单写进提款叶子
- 现在做 VM、现在做指令级二分
- 靠 `validity_proof_hash` 空槽「以后接 ZK」（Oscript 没有 pairing；升级靠拆门）
- 给金库加 owner 以便升级

---

## 6. 落地顺序（实现时，本文不改代码）

1. 记账 / 裁判 / 金库三拆；提款树只承诺钱；主张带 `version=1`。
2. `wit_root` / `trace_root` / `units_root` / `fills_root` 生成与 `validate_against` 复算。
3. 裁判谓词 + watcher 改打证明，不再广播 `{challenge:1}`。
4. inbox + P-omit。
5. 金库删 submit/lock/challenge；只托管 + 读记账门的 finalized 森林。
6. **以后真要任意合约时：** 新 VM crate、新裁判、新 `CHAIN_ID`、用户迁资金。不要在 1–5 里预埋虚拟机。

`CHAIN_ID` 在结算层切到新协议时换新值。旧金库资金走现有 finalized 提款迁出。

---

## 7. 执行规则断代记录（#47 B8）

确定性状态转移一旦改变，新版 watcher 重放旧引擎产出的高度就会得到不同的
`state_root`，误报 ROOT MISMATCH；op / 叶格式一旦改变，旧 AA 与新 watcher 也会
互判 fraud。因此 **#47 把以下全部变更合并成一次协调的链重置，并把
`ASSERTION_VERSION` 从 1 升到 2**（第 6/6b 轮再升到 3、第 7 轮升到 4、第 7b 轮升到 5、第 8 轮升到 6、第 9 轮升到 7，见下表最后五行；Rust `minuend_types::ASSERTION_VERSION` 与
`minuend_rollup.aa` 的 `assertion_version != N` 门同时修改；
`rollup_aa_pins_the_rust_assertion_version` 测试锁住两者一致）：

| 来源 | 变更 |
|---|---|
| #39 | `Place` 失败整体回滚 |
| #42 | kind-2（ADL）成交不收 taker fee |
| #44 | genesis 种子、`ORDERING_SALT_DOMAIN`、`CHAIN_ID`、gossip topic 改名（见 §8） |
| #47 执行层 | spot_only 最坏情况预留、ADL 成交价钳进价格区间、gov-nonce 水位只在成功时推进、Place/清算撤销日志、无成交的清算不留任何状态、一个地址只能绑定一个账户、对不存在账户的提款不再创建空账户 |
| #47 承诺格式 | `p:` op 增加 `typ`；`d:`/`D:` op 增加地址；witness 树增加 `adr:` 叶；快照格式 v5 |
| #47 AA | rollup / dispute / dispute_fill 定义变化，新增 dispute_bind，vault 改为按 `wit_root` 付款 |
| #47 第 9 轮 → **7** | 所有 dispute AA 的 h = 1、k = 0 pre 根改为真实 genesis 见证根 `GENESIS_WIT_ROOT`（谓词）；引擎不写 \|mark\| ≥ `MARK_CAP`（1e15）的 mark（执行语义）；dispute_mframe / dispute_claw（P-noband 移入）/ dispute_xframe / dispute_bind / dispute / dispute_fill / dispute_book / rollup 定义变化；快照格式不变 |
| #47 第 8 轮 → **6** | witness 给每个 PERP / W 持有者 `acct:` 叶（R8-C3）并新增 `obond:{acct}:{unlock}` 叶（R8-H2）（承诺格式）；新增 dispute_mframe（P-mframe / P-noband），dispute_xframe（P-xframe / P-tsize）/ dispute / dispute_bind / rollup 定义变化；快照格式不变（v9，见证叶由状态派生） |
| #47 第 7b 轮 → **5** | `Reveal{Cancel}` 的 ops 叶提交内层 `c:`（承诺格式）；第一个 maker 不足目标仓位 1/10 时清算直接 ADL（执行语义）；快照格式 v9；新增 dispute_xframe（P-xframe / P-mframe / P-noband / P-tsize），dispute / dispute_book / dispute_claw / dispute_bind / dispute_fill / rollup 定义变化 |
| #47 第 7 轮 → **4** | unit id = `sha256("mnu3\|" + hex(canonical) + "\|" + ops 描述串)`（承诺 / 签名格式，P-opbind）；每个 unit 至多一笔成交、`place` 不再同单元 force-sell、清算簿内有成交时不 ADL、ADL 只取一个对手方（执行语义）；witness 新增 `band:` 叶；dispute / dispute_book / dispute_claw / rollup 定义变化 |
| #47 第 6/6b 轮 → **3** | `Reveal{Place\|Liquidate}` 的 ops 叶提交内层 `p:` / `L:`（承诺格式）；`place` 执行 `QTY_CAP`（`\|仓位\| + 挂单剩余量 + qty < 1e15`，执行语义）；新增 dispute_claw，dispute_bind / dispute_book / dispute_fill / rollup 定义变化 |

规则：**以后再改确定性执行语义或承诺格式，必须二选一**——要么与 rollup AA
重新部署一起把 `ASSERTION_VERSION` 再升一级（并在本表追加一行），要么在
`minuend-types` 增加按高度激活的规则开关并在此登记。

## 8. #44 改名与 #47 重新部署：迁移说明（#47 B5）

#44 的“改名”并不是纯显示名变化：genesis unit id、初始 `last_finalized_root`、
加盐排序域、`CHAIN_ID` 和 gossip topic 都变了，这些都进入共识或哈希。#47
**有意把它当作一条新链**，不回退常量：

1. **旧数据不可继续使用。** 任何按 `operp-*` 常量产生的 DAG、WAL、快照都无法被
   当前代码同步（父引用指向旧 genesis → `MissingParent`；快照版本也已是 v5，旧
   快照会被自动跳过）。节点必须清空数据目录、从新 genesis 启动。
2. **旧部署作废。** `obyte-local/deployment.json` 里的旧测试网 vault
   `JZMGB3RWMUFIXQ4DBPDGFRLNLJNQAREH` 是按 `operp-mvp-1` 定义部署的（#44 把该
   记录的 `chain_id` 直接改成了 `minuend-mvp-1`，与链上事实不符）。现在它被移到
   `legacy_deployments` 并标为 `stale`，顶层地址全部为 `null`，`status` 为
   `not-deployed`；`deploy_testnet.js` / `deploy_mainnet.js` 部署后会重写该文件
   （`deploy_testnet.js` 以前构造了记录却从不写盘，已修）。
3. **新部署顺序**（两个脚本已实现）：先部署 `minuend_dispute.aa`、
   `minuend_dispute_fill.aa`、`minuend_dispute_bind.aa`（它们的定义不含 rollup
   地址）→ 把三者地址写进 `minuend_rollup.aa`（`DISPUTE_AA_HERE` /
   `DISPUTE_FILL_AA_HERE` / `DISPUTE_BIND_AA_HERE`）后部署 rollup → 把 rollup
   地址写进 `minuend_vault.aa` 后部署 vault → 依次发送 `{bind:1}`、
   `{bind_fill:1}`、`{bind_bind:1}`（各 20000 字节，`rollup` 地址放在 trigger
   数据里）→ 校验 rollup 的 `dispute_aa` / `dispute_fill_aa` / `dispute_bind_aa`。
4. **旧金库里的资金**（若有）只能用旧版本工具按旧 forest 证明取出；新金库不认
   旧根。运营方与 watcher 的环境变量统一使用 `MINUEND_*`（旧 `OPERP_*` 仍可读取
   并打印弃用警告，见 B9）。
5. watcher / poster / 节点必须**同时**升级：新 `assertion_version`、新 op 格式与
   新 `adr:` 叶，任何一方使用旧版本都会被另一方判定不一致。
