# MINUEND 协议原理

> 本文是设计动机的叙事版。逐条规则的精确参考（常量、边界情况、
> 威胁模型矩阵）见 [MECHANISMS.md](MECHANISMS.md)。


本文深入说明 MINUEND（乐观 DAG 侧链永续 DEX，结算到 Obyte）的设计原理与安全机制。
README 是概览；这里是"为什么这样设计"。

术语：

| 符号 | 含义 |
|---|---|
| unit | 用户操作的最小单元：`{parents, op, pubkey, sig}`，id = sha256("mnu3\|" + hex(canonical bytes) + "\|" + ops 描述串)（第 7 轮，MECHANISMS §10.14） |
| height | 批次序号；每个批次把侧链推进一个高度 |
| operator | 把侧链批次提交到 Obyte AA 的角色（当前为单一 operator） |
| keeper | 触发清算的账户，收取清算奖励 |

---

## 1. 共识层：乐观 DAG + 确定性全序

### 1.1 为什么是 DAG

侧链不跑 BFT 共识。用户把操作签成 unit，引用最多 2 个父单元，形成 DAG。
引擎对"父母都已执行"的 pending 单元按 `unit_id` 字典序执行——这是**确定性全序**：
任何副本拿到同一批单元，无需任何通信即可重放出完全相同的状态。

- **签名即准入**：ed25519 `verify_strict` 拒绝可延展签名；每个 op 的字段与
  签名者公钥绑定（`account_matches`），Deposit/Place/Cancel/Withdraw 必须由
  账户本人签名，Liquidate 由 keeper 签名——自我清算在密码学层就不可能。
- **乱序容忍（orphan 缓冲）**：收到父母未知的子单元时不再丢弃，而是进入
  orphan 缓冲（容量 4096，超出按盐化序 `argmin(sha256(salt ‖ unit_id))`
  驱逐；盐由最后最终化根与 epoch 派生。执行序本身是 `unit_id` 字典序、
  已去盐）。父母到达后自动链接进 pending 集合，多级孤儿链按不动点迭代解锁。
- **父单元年龄窗口 `PARENT_WINDOW`（第 2 轮 R2-R-6/7，共识规则）**：一个 unit 只有
  在它的每个父单元都位于最近 `PARENT_WINDOW = 2 × BATCH_MAX_UNITS` 个已执行单元之内
  时才执行（genesis 视为第一个单元之前执行的虚拟单元）。判定发生在执行位置，
  生产者与每个重放者完全一致；插入时若父单元已过期则提前拒绝（过期不会再变新鲜）。
  窗口等于快照持久化的锚点环 `DAG_ANCHOR_LIMIT`，所以快照恢复节点与长跑节点
  判断相同；引用远古父单元的 unit、以及执行后滑出窗口再被重发的旧单元都会被拒。
- **Reveal 账户绑定（第 2 轮 R2-E-1）**：`Reveal` 的 inner op 不能是
  Commit/Reveal，且 inner 的签名账户必须等于外层 Reveal 的账户；否则 ingest 即
  `BadSig`、执行层 `BadAccount`。

### 1.2 执行语义

```
ingest(unit):
  verify_sig(unit)                      # 严格 ed25519
  dag.insert(unit)                      # 校验/缓冲/链接
  apply_ready()                         # 对所有 ready 单元按 id 序 dispatch
```

ingest 在验签之前还检查金额可编码（R2-R-3：Deposit/Withdraw 金额 ∈
[i64::MIN, u64::MAX]，GovDeposit/GovWithdraw ≤ u64::MAX，Reveal 内递归），
越界返回 `AmountOutOfRange`、不进 DAG。

每个 op 的拒绝原因都是显式枚举值（`DuplicateClientSeq`、`UnbackedDeposit`、
`DuplicateNonce`、`Risk`、`BadAccount`…），全部进入事件日志，重放时可逐条比对。

**client_seq 连续性**：每个账户的 Place 操作携带严格递增的 client_seq
（首笔必须为 1）。这使订单幂等、重放攻击无效，也让"漏发/重发"可被精确检测。

## 2. 撮合层：CLOB 与整数定值

### 2.1 定点数

| 类型 | 缩放 | 说明 |
|---|---|---|
| Price, Qty | u64 × 1e8 | 价格 100_000 USD/BTC = `10_000_000_000_000` |
| Usd (collateral/PnL) | i128 × 1e6 | 微美元精度 |

notional = qty · price / PRICE_SCALE · USD_SCALE / QTY_SCALE

全程无浮点。入口处双重防护：
`qty > i64::MAX` 直接拒；`qty·price` 在 i128 域 checked-mul，溢出即 `Risk`。
这封死了审计中的溢出 DoS：`Place{qty: u64::MAX}` 得到的是干净拒绝而非 panic。

### 2.2 订单簿

价格-时间优先 CLOB：

- 买卖两侧各一棵 `BTreeMap<Price, VecDeque<OrderId>>`（bid 用 Reverse 包装）；
- 同价 FIFO；部分成交后余量留在原队列头部；
- IOC/GTC；taker 与 maker 同账户 = self-trade：带托管的自家挂单
  （`margin_left > 0`）拒单（`SelfTrade`），cross 挂单撤 maker 续拍；
- 每个 price level 维护增量更新的 `visible_qty` 缓存：
  成交扣减、挂单累加、撤单扣减，best_bid/best_ask 读缓存头 → O(log depth)，
  消除了原来 O(深度×队列长) 的扫描。

### 2.3 风险引擎（全仓 + 逐仓）

每次成交同时更新 taker/maker 两腿：开仓 VWAP 入场价，平仓实现 PnL。

**全仓快照**（`Account::snapshot`，按市场参数取费率）计算：

```
mm (maintenance) = bps(|qty|·mark, market.mm_bps)   创世默认 500
im (initial)     = bps(|qty|·mark, market.im_bps)   创世默认 1000
equity           = collateral + unrealized_pnl
                   （已实现 PnL 平仓即结算进 collateral）
liquidatable     : equity·10000 ≤ mm·10500
reduce_only      : equity·10000 ≤ mm·12000
```

开仓前检查 `equity ≥ im(仓位) + resting_open_im(挂单预留) + 本次开仓 im`；
`resting_open_im` 对每个市场、每侧先求该侧挂单名义额之和，再按**开仓数量**
计价：开仓部分 = 该侧挂单量 − 可被该侧抵消的仓位量（bid 抵消空头、ask 抵消
多头），预留 = `该侧名义额 × 开仓量 ÷ 该侧挂单量`（先乘后除，不截断），
再取 `max(bid 侧 im, ask 侧 im)`（两侧最终不会同时开仓）。挂单数另有上限：
每账户全簿 live 单 ≤ 64（含不会驻留的 IOC）。开仓单还要求 `equity ≥ $1`
且估算价非零、名义额非零（无 mark 的市价单被拒，防零保证金开仓）。

市场参数统一经 `risk_params_ok` 校验，CreateMarket 与治理提案（创建时预检 +
finalize 落盘前复检，非法提案为 no-op 但仍消耗）共用同一谓词：

- 普通市场：四个 bps 非零且 ≤10000、im>mm、mm≥500、im≤5000、taker≤200、
  keeper≤500、im ≥ 10×FUNDING_CAP_BPS、`funding_cap_bps == 0`；
- 资金费率市场：im≥100、mm≥50、`funding_cap_bps ∈ [1,500]`、
  im ≥ 10×cap、keeper ≤ im/10；
- `spot_only` 市场：`im == 10000`（全额抵押，不受 im≤5000 限制）、
  mm≥500、im>mm、taker∈[1,200]、keeper∈[1,500]，且不得同时为资金费率市场。

`spot_only` 市场还必须声明价格区间 `0 < min_price < max_price`；其仓位不用
（冻结的）mark 计保证金，而是按区间最坏情况预留现金（多头跌到 `min`、空头
涨到 `max`，另加 taker 费，且不少于全额名义额），预留从 equity 中扣除，见
docs/MECHANISMS.md「spot_only 的偿付不变量」。提款后既不得落入 reduce-only，
也不得使 equity（已扣除 spot 预留）为负。

**逐仓模式**（`Place { isolated, margin }`，mode 在 order 上、无新 Op）：

- **模式唯一**：同账户同市场的敞口只有一种模式——已有仓位的模式优先，
  否则取该市场第一张活挂单的模式；不符即 `Risk`。flat 且无挂单的账户
  以订单自身的 mode 为准。
- **保证金字段规则**：跨仓单 `margin` 必须为 0；逐仓纯减仓单 `margin`
  必须为 0（无开仓敞口可支撑，意义不明即拒）。
- **开仓门槛**（逐仓分支）：`margin ≥ max(extra_im, 1)`（至少 IM、至少
  1 个 USD 单位）、`margin ≤ collateral`、escrow 后跨仓池仍健康
  （equity − margin ≥ im + resting）。**不适用** `MIN_OPEN_EQUITY`——
  margin 下限就是它的等价物。
- **托管生命周期**：下单时 `collateral -= margin`；成交按量比例
  （pro-rata，最后一笔吃掉余数）把 margin 记入该市场的 `isolated_margin`
  桶并进仓位；撤单/未驻留余量退回 collateral。自成交（STP）：cross
  撤 maker 续拍（`margin_left = 0`，不动现金）；带托管的自家挂单由
  place 路径拒单（`SelfTrade::Reject`）——其撤单退款无法被填充谓词的
  精确恒等式建模。
  守恒不变式：`collateral + Σisolated_margin + Σlive margin_left`
  只经 deposit/withdraw/PnL 变动。
- **风险隔离**（`isolated_risk(market)`）：equity = 桶 + 该仓 uPnL，
  `snapshot` 完全跳过逐仓仓位（跨仓权益/IM/可清算性
  看不见它）。mark 缺失 → reduce_only，equity = 桶。清算判定逐仓走
  `isolated_risk`、跨仓走 snapshot；平仓释放比例桶进 collateral 后
  才结算 PnL。逐仓是风险计算与开仓保证金边界，不是坏账担保：成交可使
  collateral 为负，随后仅按 §2.4 从非保险对手方可用正抵押有限 clawback；
  未覆盖的负余额仍保留，保险不补。

### 2.4 清算、keeper 与保险基金

- 第 7 轮起每个 unit 至多产生**一笔**成交：Market / IOC 单吃到第一个 maker 即停，Limit + Gtc
  单若还会吃到第二个 maker 则整单拒绝；`Place` 不再在同一单元内 force-sell 仍可清算的成交方
  （留给之后的 keeper `Liquidate`）。
  keeper 发起的 `Liquidate` 由 `caller` 签名，禁止自我清算，也不能把保险账户
  作为 caller 或 target。普通市场先用 Market IOC 吃簿（一笔）；簿内没有成交且目标仍可清算时，
  按 mark 价（夹进价格带）ADL 给一个反向持仓者，按仓位绝对值降序、`AccountId` 升序选第一个。
  剩余仓位留给下一次 `Liquidate`，不由保险基金接盘。
- 普通双非保险方成交若使一方 collateral 为负，只从另一方可用正 collateral
  clawback：金额不超过其可支付余额、转账保持零和。余额不足时缺口仍留在负
  collateral，不会把 equity 钳零或转记保险基金。
- `funding_rate` 市场走独立离簿清算：以新鲜外部指数平仓、缺失时回退非零 mark，
  ADL 后的残余缺口按比例从本次 ADL 对手方的正收益扣减；无法覆盖的部分仍留在
  目标账户。该路径不向保险基金索赔。
- keeper 奖励按市场 `keeper_reward_bps` 和本次清算成交名义额计算，只从被清算方
  的正 collateral 扣款；不足则只付可用余额。创世市场默认 100 bps。保险基金创世
  注入 10 000 USD，接收 taker 手续费，但不支付交易坏账或 keeper 奖励，也不作
  清算的 ADL 对手方。
- **mark 多重防线**：① notional ≥ 100 USD 才可更新；② 新价相对旧 mark
  偏离不得超过 ±10%；③ 一旦市场有债券注册报价者的报价（`Op::ReportPrice`，
  全部已质押报价者最新价的**中位数**，§7），成交价即失去 mark 定价权——
  非零 mark 还需已有 `last_index`（报告者指数）才允许继续移动，否则首个
  fill 之后 mark 冻结；④ oracle 写入的 mark 还须落在 funding index 的
  ±10% 带内（带外保留旧 mark，无 mark 则以 index 自举）。
  资金费率：有效报告数 ≥ 2 时**每高度至多一次**结算，按
  (spot − index)/index（钳 ±50bps）在多空之间转移。付款方借记被钳在其
  可用抵押内，收款方入账以实际扣减总额封顶——严格守恒、不产生负余额；
  保险基金作为普通账户参与（可持有清算对冲仓位）。
  `funding_rate` 市场不走溢价结算：报价只写 `last_index`，mark 由
  fill 写入，资金费按 peg 结算（`settle_funding_peg`：首个观测只 arm
  `last_funding_height`，此后每 14_400 高度窗口总是重 arm，且仅在存在
  新鲜外部打印时按 `funding_rate_cash(qty, clamp(mark 费率 − 指数费率,
  ±市场 funding_cap_bps), usd_per_unit)` 付款——无打印则该窗口不付；
  时钟进 meta 叶承诺）。

### 2.5 市场准入与存款白名单

- 市场无许可上架：`markets: BTreeMap<MarketId, MarketParams>` 创世仅含
  BTC_USD，其余任何人可经 CreateMarket 烧毁 `CREATE_MARKET_FEE_PERP` 上架费
  创建（IM/MM/费率成为每市场参数）——上架有真实成本，任意 `MarketId(u32)`
  无法撑爆 books / Merkle 叶子集合。
- `deposits_allowed: HashSet<aa_unit>`：deposit op 引用的 AA 存款事件必须出现在
  本批次窗口的白名单里，否则 `UnbackedDeposit` 拒绝——存款不能凭空铸造。
生产路径中该集合来自真实 Obyte AA 存款事件（金库 `dep_` / `depp_` 记录）；replay 时由
`validate_against` **按 unit** 登记（第 4 轮 R4-E-1/E-4）：evidence 只盖在生产者
**实际执行成功**的那个充值帧上，重放只在执行该 unit 前登记它的锚点，该 unit 未执行成功
则撤销登记；引用同一锚点的其它 unit（抢跑、重复、跨类别、在金库记账前签的）都看不到
登记，与生产者一样被拒。evidence 的认定规则与金库记账逐条一致（R4-E-2：第一条 data
消息、按金库地址**求和**全部输出、`deposit` / `deposit_perp` 的 Oscript 真值与 case 顺序、
金额 > 0、PERP 资产 id、10000 bounce 费、`max_aa_responses`），见
`deposit_verify::vault_deposit_of`。**生产者要求**：只有当金库记录存在且
`deposit_verify::admit_deposit(evidence, vault, PERP, 记录)` 通过时才 `allow_deposit`，
并为执行成功的充值帧附上该 evidence。R5-E-1：大小上限三级严格递增——生产者登记
单份 ≤ 240 KiB（`admit_deposit`）、整批 ≤ 960 KiB（执行充值**之前**由
`DepositEvidenceBudget` / `ingest_within_budget` 检查，放不下的充值留到下一批）<
`post_batch.js` 发帖 248 KiB / 992 KiB < watcher 验证 256 KiB / 1 MiB。
每个登记的锚点都带 `deposit_backing = (amount, payer, account)`（`allow_deposit`），
Deposit / GovDeposit 必须与之完全一致：账户不同 → `BadAccount`，金额或地址不同 →
`UnbackedDeposit`；被拒 unit 不使批次无效，但任何 Applied 的充值必须有验过的 evidence。
Replay 核对 joint 哈希、实际付款内容与 payload_hash、data 消息里的指定账户、调用方绑定的
vault/asset，并要求 joint 首作者 = evidence payer。该本地证据校验不证明
joint 已进入 Obyte 主 DAG 或获得稳定；AA 谓词路径本身不验证这类 L1 事实。

## 3. 结算层：状态根与争议承诺

每 ≤200000 units（BATCH_MAX_UNITS）/ 2 秒切一个批次，产出 Checkpoint：

```text
{ height, prev_state_hash, state_root, aa_shard_roots[16], aa_root,
  last_unit, seq, unit_ids, fills_hash, fill_count, assertion_version,
  wit_root, trace_root, units_root, units_set_root, ops_root, fills_root,
  counts_root, unit_count, wit_count,
  validity_proof_hash?, perp_burned? }   # 可选字段：旧批次缺省
```

`aa_root` 是 16 个 shard 根拼接的 1024-hex `aa_forest` 的森林哈希
（`aa_forest_hash`）；`validity_proof_hash` 为可选透传字段（AA 不作门）。
`assertion_version` 当前为 **6**（#47 B8 升到 2；第 6/6b 轮升到 3；第 7 轮升到 4；第 7b 轮升到 5；第 8 轮升到 6，见 ROLLUP-UPGRADE §7），
rollup AA 只接受等于 5 的提交。

### 3.1 state_root（字节域 Merkle 树）

叶子 = 账户叶 ∥ 订单簿叶 ∥ meta 叶 ∥ 每个已消费充值 `aa_unit` 的独立
`dep` 前缀叶，排序后两两合并（奇数复制末位）。充值锚点集合永久保留，
不随普通 replay 窗口剪枝，防止旧 AA 付款再次入账：

```
account_leaf = sha256("acct" ‖ id32 ‖ collateral_i128le16 ‖ realized_i128le16
                      ‖ pos_count_u32 ‖ [market_le4 qty_le8 entry_le8]*
                      ‖ iso_count_u32 ‖ [market_le4 margin_i128le16]*
                      ‖ perp_u128le16 ‖ withdrawn_i128le16)
               # iso = 逐仓保证金桶（BTreeMap 序，§2.3），已出 collateral
               # perp = PERP 治理余额（§7），与抵押并列进入承诺
               # withdrawn = 累计已签名提款额 W（vault 校验 本次+历史 ≤ W）
book_leaf    = sha256(params_91B ‖ 簿承诺)
               # params_91B = symbol16‖tick_le8‖im_le8‖mm_le8‖taker_le8
               #   ‖keeper_le8‖delisted1B‖spot_only1B‖funding_rate1B
               #   ‖usd_per_unit_le8‖funding_cap_bps_le8
               #   ‖min_price_le8‖max_price_le8
               #   ——市场参数本身成为被承诺状态
meta_leaf    = sha256("meta" ‖ 全部规范化共识元数据)
               # 包含 height/seq/last_unit、市场与预言机状态、资金费时钟、
               # commit-reveal、治理提案/投票及 PERP 供应等；精确序列化见
               # docs/MECHANISMS.md §9.1，不限于下方示意字段
```

**meta_leaf 包含 height**，且 `from_applied` 执行后会把 `engine.state.height`
推到 checkpoint.height 再取根——于是 state_root 与高度绑定，
`prev_state_hash` 链条真正具备防重组性质：改历史高度必然断链。

### 3.2 aa_root（字符串域分片森林，专为 AA 设计）

> **#47 A2 起，金库不再按这棵森林付款。** 森林的叶子从不公开（DA 里只有
> 16 个 shard 根），任何争议谓词都无法指向一片伪造的森林叶，所以它不是一个
> “可挑战”的承诺。金库改为对**最终 witness 根**（`wit_root_<h>`，§3.4）
> 证明 `adr:` 与 `acct:` 两片叶子；森林保留为与 `aa_root` 哈希绑定的信息性
> 承诺。下面的描述仅作格式记录。

Oscript 的 `sha256()` 对参数的 UTF-8 文本做哈希（默认输出 base64！）。
字节级树无法在 AA 内复算，因此另建一棵**同构但键为字符串**的树，并打成
**16 棵 shard 树拼接的 1024-hex `aa_forest`**：

```
leaf = sha256_hex("acct:" ++ address ++ ":" ++ collateral十进制串
                  ++ ":" ++ perp十进制串 ++ ":" ++ withdrawn十进制串)
node = sha256_hex(left ++ right)
aa_forest = shard0_root ‖ … ‖ shard15_root     # 恰好 1024 hex
```

Rust 侧 `aa_sharded_forest` / `aa_sharded_proof_for_account` 构造与证明；
AA 侧用纯字符串拼接 + `sha256(x, 'hex')` 在声明的 shard 内复算，再
`substring(shard*64, 64)` 取出该 shard 根。两棵承诺完全相同的
(地址, 抵押, PERP, W) 集合。空 shard 提交哨兵根
`hex(sha256("empty:<shard>"))`，零证明无法跨 shard 跳动。

### 3.3 fills_hash / fill_count / fills_root

成交流的规范编码（taker_id‖maker_id‖price‖qty‖seq）哈希。`from_applied` 与
`validate_against` 共享 `fills_bytes()`，replay 时重算比对——operator 漏报/
谎报成交会被直接抓住。另有 AA 用的 `fills_root`：成交描述串后追加尾随
`n:<len>` 长度哨兵，作为末笔成交的右邻证明；它独立于 `fills_hash` 和
`fill_count`；零成交批次的根是单叶 `n:0`。`fill_count` 仍保留在提交头和
rollup 状态，但 fill dispute 不依赖该整数来判定末笔。

```
assert chain_id == CHAIN_ID          # ChainMismatch
assert replay.state_root == prev     # PrevMismatch
inject deposits_allowed ← batch 内 Deposit ops 的 aa_unit 集合
ingest(units…)                       # BadSig → Replay
recompute fills_hash/fill_count      # FillsMismatch
assert checkpoint.height == replay.height + 1
set replay.height = checkpoint.height
assert last_unit 一致 ∧ replay.state_root == root   # RootMismatch
```

TooManyUnits 上限（200000）在 from_applied 就挡住超大批次。

### 3.4 witness 叶（`wit_leaves`，Obyte merkle，争议 AA 与金库共用）

排序后的字符串叶，`obyte_merkle::root`（与 Oscript `is_valid_merkle_proof`
同一算法）；每个已执行单元（含被拒单元）后的根依次进入 `trace`：

```
acct:{acct_hex64}:{collateral}:{perp}:{W}
pos:{acct_hex64}:{market}:{qty}:{entry}:{isolated 0|1}:{bucket}
ord:{order_hex}:{market}:{side}:{price}:{seq}:{remaining}:{acct_hex}:{isolated}:{margin_left}
adr:{obyte_address}:{acct_hex64}          # #47 A2：地址 → 账户绑定
adrx:{acct_hex64}:{obyte_address}         # 第 2 轮 R2-A-8：账户 → 地址反向镜像
dep:{aa_unit_base64}                      # 第 2 轮 R2-A-3：已消费充值锚点（永久）
meta:{market}:{tick}:{im}:{mm}:{taker_fee}:{keeper}:{delisted}:{mark}:{usd_per_unit}:{funding_cap}
~:end                                     # 第 2 轮 R2-A-5/10：最大哨兵，恒为最后一叶
```

- 第 2 轮起树永不为空、恒以 `~:end` 结尾：任何键不存在都可用相邻两叶证明，
  谓词不再有"在最大叶之后"分支、不再读 `wit_count`（仍提交，仅信息性）。
  `wit_leaves` 是现有状态的纯函数，state_root / 快照布局不变。
- `adrx:` 让"账户已绑定某地址"可用成员证明表达（P-adr 拒绝第二个地址）；
  `adr:` ↔ `adrx:` 由 P-mirror 钉成对，`adrx:` / `dep:` 由 P-keep 钉永久。

- `adr:` 叶按地址排序，所以“某地址没有绑定”可以用相邻两叶做非成员证明。
- 引擎保证**一个地址最多绑定一个账户**（`deposit` / `gov_deposit` 在地址已属于
  别的账户时 `BadAccount`），且绑定只在操作**成功**后写入。
- 金库提款：`adr:{trigger.address}:{acct}` 与 `acct:{acct}:{col}:{perp}:{W}`
  都必须证明在 `wit_root_<last_finalized>` 中，再按 `amount + wd_ ≤ W` 付款。
- `minuend_dispute_bind.aa` 对**每个单元**钉住金库读取的两列：
  - P-wpin：`W` 只能在该账户自己的 `w:` op 下变为 `W + amount`，否则不变；
  - P-adr：新出现的 `adr:{A}:{X}` 必须对应 `d:`/`D:` op 且 op 的账户为 X、
    地址为 A；已有绑定不得改指向；账户已有 `adrx:{X}:` 时不得再绑新地址（R2-A-8）；
    第 4 轮（R4-A-4）：新绑定还要求金库 `dep_<anchor>`（`D:` 为 `depp_<anchor>`）记录
    存在且 payer == A、account == X（bind AA 用 `VAULT_BASE` + rollup 推导金库地址）；
  - P-frame（R4-A-3）：`c:`/`d:`/`w:`/`D:`/`W:` 单元中 `pos:` / `ord:` 叶不得出现、消失
    或被改写，唯一例外是 `c:` 撤掉的属于该账户的订单；
  - P-tip（R2-A-1）：trace 末元素（下标 `unit_count-1`）必须等于 `wit_root_h`；
  - P-keep / P-mirror：见上。
  被拒单元两列都不变，所以“未变化”永远不会被判 fraud。

### 3.5 op 描述串（`ops_element`，`ops_root` 承诺）

```
d:{acct}:{amount}:{addr}:{aa_unit_b64}                    # 第 2 轮 R2-A-3：5 段，带金库锚点
D:{acct}:{amount}:{addr}:{aa_unit_b64}                    # 第 3 轮 R3-A-7：PERP 充值也带锚点（5 段）
w:{acct}:{amount}:{nonce}    W:{acct}:{amount}:{nonce}
c:{acct}:{order_hex}
p:{acct}:{market}:{side}:{price}:{qty}:{isolated}:{margin}:{tif}:{typ}   # #47 A3：typ 0=Limit 1=Market
L:{caller}:{target}:{market}
x:{unit_hex}                                               # 其他 op
```

第 2 轮 R2-E-2：`Reveal{inner}` 的 inner 为 Deposit/GovDeposit/Withdraw/GovWithdraw
时输出 inner 的描述串（`d:`/`D:`/`w:`/`W:`），其余 Reveal 仍为 `x:`。P-deposit 的
入账分支要求：金库 `dep_<aa_unit>`（`D:` 用 `depp_<aa_unit>`）记录 =
`{payer}:{amount}:{account}` 存在且 payer == op 地址、**account == op 账户**（第 3 轮
R3-A-5：存款人自己在付款 data 里指定入账账户）、amount ≤ 记录值，pre 树无 `dep:{u}`
（防重复入账），post 树有 `dep:{u}`，且 post 树有绑定叶 `adr:{addr}:{acct}`（第 3 轮
R3-A-4，挑战者可用 `aleft/aright` 证明其不存在）。

第 3 轮其它规则：被接受的 `w:` 之后 collateral 不得为负、pre 不存在的账户的 `w:`
只能是被拒（R3-A-1，P-withdraw 与 P-wpin 同步）；P-escrow 只认 `acct:` 叶
（R3-A-2）；P-keep 覆盖 `acct:` 叶（账户只会变、不会消失，按 `[acct:X:, acct:X;)`
区间证明缺失，R3-A-6）；fill_math 的 collateral 恒等式容差 ±6，任何量级 ≥ 1e14
或成交阶段 collateral < 6 时 bounce（Oscript 只有 15 位有效数字，R3-A-3）。

第 4 轮 AA 规则：
- **P-mbind**（R4-A-1，dispute_book）：成交的 maker 订单在 pre_wit 中存在但与成交不符
  （owner、市场、方向、价格不同，或剩余量 < 成交量）即欺诈；订单不存在仍归 P-ghost。
- **P-frame**（R4-A-3，dispute_bind）：见 §3.4。Place / Liquidate / `x:` 单元不覆盖。
- **R4-A-5**（dispute_fill）：量级 / 近零门只跳过 collateral 腿，仓位、perp/W、op、挂单
  余量腿始终判定；价格 / entry / qty ≥ 1e14 时跳过仓位数值比较，bucket / mml / tpost ≥ 1e14
  跳过 bucket 比较，margin ≥ 1e14 跳过托管份额比较，op qty ≥ 1e14 跳过挂单余量比较。
- **R4-A-6**：引擎 `PERP_SUPPLY_MAX = 99_999_999_999_999`（< 1e14，`gov_deposit` 超限以
  `Risk` 拒绝，检查在绑定之前），所以 PERP 列 ≤ 14 位；dispute AA 的 gov 旧账户分支在
  pre PERP > 14 位时 bounce，算术只在 post PERP 与 amount ≤ 14 位时进行。

第 5 轮 AA 规则（MECHANISMS §10.11）：
- **P-frame**（R5-A-1）：也覆盖 op 账户以外的 `acct:` 叶（这些单元不改别人的账户）。第 7c 轮（R7b-N2）起这部分由 dispute_xframe 的 P-xframe 按 pre / post 比对判定（k = 0 放行批次边界退回的 `+ORACLE_BOND_PERP`；PERP 只允许 `D:` / `W:` 的 op 账户变化），dispute_bind 的 P-frame 只判 `pos:` / `ord:`。
- **fill_math**（R5-A-2 / R5-A-4）：collateral 腿按 claw 区间判定，没有跳过门；容差
  `6 + floor(S/1e12)`，S 只含已证明的量；bucket、op 份额、挂单余量都带比例容差判定；
  kind 2/3 只在资金费率市场或逐仓目标时 bounce；`x:` taker 只判 collateral 上限；
  删除 `eleft`/`eright` 臂（用 `post_pleft`/`post_pright`）。
- **P-fsane**（R5-A-2，dispute_book，`pred: 'fsane'`）：成交形状 / kind 与 meta / op margin /
  成交方 pre 账户存在性，只凭已证明的值。
- **P-mbind**（R5-A-3）：qty 数值比较 `!is_integer(q) OR q <= 0 OR q > MO[6]`。
- **金库 PERP 上限**（R5-A-5）：`pperp_total + amount > 99999999999999` → `bounce('perp cap')`
  （PERP 退回、不写 `depp_`）。`vault_deposit_of` 只镜像无状态部分（单笔 > 上限）；因额度已满
  被 bounce 的充值由生产者 / `post_batch.js` 的 `depp_` 记录核对与 watcher 的 hub 读取覆盖。

第 6 轮 AA 规则（MECHANISMS §10.12）：
- **P-claw**（dispute_claw，`pred: 'claw'`）：单成交 unit 的两条腿一起判——按引擎重算 taker 与
  maker 的成交阶段 collateral、claw（先 taker 后 maker，零和）、逐仓 taker 未留簿托管的退款
  与 keeper 扣取（都在 claw 之后），任一方 post collateral 偏离超过
  `4 × (16 + floor(S/1e12))` 即欺诈。范围：普通市场的 kind 0（taker 自己的 `p:` 下）与
  kind 2/3（`L:{caller}:{taker}:{market}` 下、cross target），taker ≠ maker、都不是保险账户。
- **Reveal 转发**：`Reveal{Place}` / `Reveal{Liquidate}` 的 op 串是内层的 `p:` / `L:`
  （此前是 `x:{unit}`）。

第 6b 轮规则（MECHANISMS §10.13）：
- **成交 ↔ op 绑定（R6-C1，P-claw）**：unit 的第一笔成交（任何笔数、任何市场）若不是其 op 的
  （op 不是 `p:` / `L:`；`p:` 的账户 / 市场 / 方向 / 下单量 / kind ∈ {0,1} 不符；`L:` 的市场不符、
  target 不在成交里、caller = target 或保险账户、kind ∉ {2,3}；成交量或下单量 ≥ 1e15）即欺诈。
  普通市场上 kind 1、或 `L:` target ≠ taker 也是欺诈。
- **第三方账户（R6-C2）**：P-frame 覆盖普通市场的零成交 / 单成交 `p:` / `L:` 单元（`fill` /
  `fright` 相邻 fills 叶 + `fill_up` / `fright_up` units 证明定笔数），op 账户、caller、target、
  maker、保险账户以外的 `acct:` / `pos:` / `ord:` 叶冻结；P-claw 的 `x_who` 判 caller 恰好得到
  `kpay`、保险账户恰好得到 fee。
- **QTY_CAP（R6-H1，执行规则）**：`place` 拒绝 `|仓位| + 该市场挂单剩余量 + qty ≥ 1e15` 的
  下单；P-fsane 判成交量 ≥ 1e15 为欺诈，P-claw / fill_math 对 ≥ 1e15 的 pre 仓位 bounce。

第 7 轮规则（MECHANISMS §10.14）：
- **P-opbind（项 10）**：unit id = `sha256("mnu3|" + hex(canonical) + "|" + E)`，E 是该 unit 的
  ops 描述串（无则 `x`）。挑战者提交在第二个 `|` 处切开的 `u_pre` / `u_op`；`sha256(u_pre‖u_op)`
  等于 units 叶 k、而 ops 叶 k ≠ `u_op`（`x` → `x:{id}`）即欺诈。
- **一笔成交（项 19，执行规则）**：每个 unit 至多一笔成交；P-fsane 判 idx ≠ 0 的成交为欺诈。
- **ADL 价格（项 28）**：witness 新增 `band:{market}:{min}:{max}` 叶；普通市场 kind 2 成交价
  ≠ clamp(pre mark, band) 时 P-claw 判欺诈（给出 band 证明时）。

第 7b 轮规则（MECHANISMS §10.15，x-frame AA = `minuend_dispute_xframe.aa`）：
- **精确证明深度**：对 ops / units / trace（`unit_count` 片叶）与 fills（`fill_count + 1`）的证明，
  siblings 数必须恰好是 `ceil(log2(c))`（`c == 1` 跳过），内部节点因此不能冒充叶（node-as-leaf）。
  **P-tsize**：叶形状元素（ops / fills 含 `:`、units 64 字符、trace 44 字符）对已提交的根有效、
  深度却不等于计数的深度 → 欺诈（树大小与计数不符）。
- **P-fsane**：fills 的 `n:{fill_count}` 哨兵不是成交（bounce）；同一 unit 的第二笔 idx 0 成交
  （左邻也是 `f:{U}:0:`）是欺诈；F[1] 必须 64 字符。
- **P-xframe**：`x:` 单元里任何 `pos:` / `ord:` 叶变化、W 变化、非 op 账户的 PERP 变化（k = 0 的
  `+ORACLE_BOND_PERP` 例外）、collateral 变化（资金费 op 0x06 / 0x11 下仅限无仓位账户）是欺诈；
  op tag 与 op 账户从 `u_pre`（unit 文本前缀）读出。`Reveal{Cancel}` 提交内层 `c:`。
- **P-mframe / P-noband**：`band:` 只在 CreateMarket 出现、永不删除 / 改写；`meta:` 参数只在
  FinalizeProposal 变化、mark 只在 `p:` / `L:` / 价格 op 变化、meta 永不删除、只在 CreateMarket
  新建；每个 `meta:{m}` 都必须有 `band:{m}`。
- **灰尘清算（执行规则）**：第一个会被吃的 maker 剩余量 × 10 < 目标仓位时，清算跳过簿、
  本 unit 直接 ADL（一个对手方）。

**被拒单元同样提交**（每个执行过的单元都占一个 trace 位置、一个 op 串）。
因此所有按 op 判定的谓词都把“相关列不变”视为诚实结果（被拒），只有既不是
“不变”也不是“正确变化”的值才判 fraud（#47 跨 PR 一致性修复）。

### 3.6 DA 分帧（#47 B11）

`frames_blob`（内联）或 `packages`（多包）二者**恰好一个**；`data_root` 承诺
**原始拼接字节**（多包按顺序直接拼接，不做任何归一化），解析的就是这串字节：

- 合法 UTF-8，不允许 `\r`；
- 帧之间恰好一个 `\n`；不允许空帧（开头、结尾、连续 `\n` 都拒绝）；
- 后续包以 `\n` 开头即可衔接，一帧可以跨包切开（只看拼接结果）。

#39 之前“包边界无分隔”和“末尾带 `\n`”的写法不再被接受（主网未上线，现有
Rust / JS 生产者都不产生这两种形状）。

### 3.7 DA 绑定 da_bind（第 2 轮 R2-R-1）

submit 单元恰好一条 temp_data（header）+ 一条 data（submitData）。两者都带
`data_root`（64 hex）、`counts_root`（44 b64）与：

```
da_bind = hex(sha256(join('|', ['minuend-da-v1', chain_id, height, prev_state_hash,
  state_root, aa_root, wit_root, trace_root, units_root, units_set_root, ops_root,
  fills_root, counts_root, unit_count, wit_count, fill_count, assertion_version, data_root])))
```

rollup 重算并要求相等（否则 `bad da_bind`），存 `da_bind_h / da_hash_h / data_root_h /
counts_root_h`。header 内容 == 链上根不可链上证明，由 watcher 检查（不符 ⇒
DA MISMATCH，高度不验证）。帧由 `post_batch.js` 逐字节透传（R2-R-4，
`frame_stamp.js` 只在充值帧末尾拼 `"e"` evidence），`data_root` 覆盖透传后的字节。

## 4. 结算层：七个 AA、多类谓词（CHAIN_ID=minuend-v2）

第 6 轮：新增 `minuend_dispute_claw.aa`（P-claw），与其它 dispute AA 一起在 rollup 之前部署；
rollup 多一个占位 `DISPUTE_CLAW_AA_HERE`、case `{set_dispute_claw:1}`、变量 `dispute_claw_aa`，
verdict 也接受它；claw AA 用 `{bind_claw:1, rollup}` 绑定。

第 2 轮部署单元：vault base → dispute / dispute_fill / dispute_bind / dispute_book
（dispute 硬编码 vault base）→ rollup（硬编码四个 dispute 地址）→ vault 实例
`{base_aa: vault_base, params:{rollup}}` → 四个 dispute 各自 `bind*` 到 rollup。
金库实例由 base + rollup 唯一确定，dispute AA 用 `chash160` 推导它并读 `dep_` 账本。

状态变量（rollup AA；`<h>` 为高度后缀）：

```
last_submitted, last_finalized, dispute_aa, dispute_fill_aa, dispute_bind_aa, dispute_book_aa,
  dispute_claw_aa             # 第 6 轮
submitted_at_h, state_root_h, aa_forest_h (1024 hex), prev_h,
  wit_root_h, trace_root_h, units_root_h, units_set_root_h,
  ops_root_h, fills_root_h, counts_root_h, unit_count_h, wit_count_h, fill_count_h
da_unit_h                     # DA 绑定 = 组合单元 hash
data_root_h, da_bind_h, da_hash_h   # 第 2 轮 R2-R-1（§3.7）
slash_burned                  # 第 2 轮 R2-A-9：罚没中锁定的 4/5
active_bond_<h>, fee_winner_<h>, frozen_<h> ∈ {∅/0=live, 2=failed}
inbox_<unit_id_hex>, inbox_upto_<h>   # inbox_upto = submit 时间戳
pool_<addr>                    # 常备池：提交门 pool>=1e12
sbond_<addr>, reward_<addr>, slash_reward_<addr>   # sbond 仅遗留路径
```

侧链 ChainState（PERP 治理，§7）不变：markets、perp_balances/supply/burned、
proposals、oracle 账本。金库 vault AA 只有 `deposit` / `deposit_perp` /
`withdraw`，提款读 `var[params.rollup]['wit_root_'||h]`，h ∈ (lf−32, lf]（缺省
last_finalized；#47 A2，§3.4；第 2 轮 R2-A-12）。金库状态：`wd_<account>`（按账户
累计已提，R2-A-8）、`wp_<addr>`、`pperp_<addr>`、`pperp_total`（R5-A-5，≤ `PERP_SUPPLY_MAX`）、`dep_<unit>='{payer}:{amount}:{account}'`
（R2-A-3 + R3-A-5）、`depp_<unit>='{payer}:{amount}:{account}'`（R3-A-7）。存款必须带
`{deposit:1, account:<64 位小写 hex>}`（PERP：`{deposit_perp:1, account}`），否则 bounce；
DepositEvidence 新增 `account` 字段（= joint 中 data 消息的 account，payload_hash 校验），
引擎只给该账户入账/绑定，其他账户引用该锚点的 Deposit 被拒（BadAccount，不使批次无效）。

执行层第 2 轮新增的提款限制（只会拒更多，AA 无需感知）：每账户在 2048 高度
修剪窗口内最多 `MAX_PENDING_WITHDRAWALS_PER_ACCOUNT = 64` 笔待处理提款（取代全局
`WITHDRAWALS_CAP`）；`MIN_WITHDRAW_AMOUNT = 1 USD`，更小的正数提款只在等于全部
collateral（清仓）时允许；提款后 equity 必须仍覆盖挂单开仓保证金（R2-E-3）。
cross 现货与非现货敞口不得混用（R2-E-8），`spot_only` 仓位永不被清算（R2-E-4）。
快照格式 `SNAPSHOT_FORMAT_VERSION = 8`（第 3 轮：v7 `deposit_backing`，v8 其值含
指定账户），由布局指纹测试钉住。

第 3 轮执行层（只会拒更多）：Reveal 不能包装 Deposit/GovDeposit（R3-E-1）；现货 GTC
限价单一律按全部数量占用储备，逐仓现货 GTC 减仓单需带足 margin，纯减仓用 IOC/市价单
（R3-E-2，取舍）；`resting_open_im` 逐仓挂单扣除 `margin_left`、现货挂单不与仓位轧差；
逐仓 taker 手续费逐笔成交前检查（R3-E-4）；`spot_only` 市场不得提高 taker 费率（R3-E-6）。
fill_math 容差 ±6（R3-A-3）的代价：每条成交腿最多 6 个最小单位的错记无法被挑战。

第 8 轮规则（MECHANISMS §10.16，m-frame AA = `minuend_dispute_mframe.aa`）：
- **witness**：每个持有 PERP 或 W 的账户都有 `acct:` 叶（没有 `accounts` 条目时 collateral 0）；
  每个质押中的预言机一片 `obond:{acct}:{unlock}`（unlock 0 = 未解押）。
- **P-mframe**（m-frame AA）：`x:` op 必须带 `u_pre`；0d 只改一个参数到合法组合或 delist；
  mark 只在 op 自己的市场变化（`p:` / `L:` = 本 unit 成交价，06 = 已质押、普通非 spot 市场、
  ±10%；11 不改 mark）；`obond:` 叶只按 0e / 0f / 0x10 / 批次边界出现、消失。
- **P-xframe**：所有比较的下标在 `[0, 叶数)` 且深度精确；`x:` op 的 op 账户 PERP 只能按
  0e −50000 / 0a −10000 / 0x10 +25000 变化；06 / 11 下 collateral 变化可由"X 在该市场无仓位 /
  预言机无 bond / 该市场不付资金费"三类证据判欺诈；k == 0 的 +50000 可由"X 没有到期的
  bond"证据判欺诈。
- **P-frame**（dispute_bind）：同样的下标边界。**P-deposit**：gov `D:` 在新账户上产生
  `acct:X:0:{amount}:…` 视为已入账。

第 8 轮部署变化：新增 dispute_mframe（rollup 新占位 `DISPUTE_MFRAME_AA_HERE`、新 case
`set_dispute_mframe`、verdict 白名单）；dispute_xframe（P-mframe / P-noband 移走，P-tsize 留下）、
dispute（P-deposit pre-absent gov）、dispute_bind（下标边界）、rollup（版本门 6）定义变化；
witness 叶格式变化（`obond:`、PERP-only `acct:`）是共识变化。op 预算见 MECHANISMS §10.16；
rollup 只接受 `assertion_version == 6`。

第 7b 轮部署变化：新增 dispute_xframe（rollup 新占位 `DISPUTE_XFRAME_AA_HERE`、新 case
`set_dispute_xframe`、verdict 白名单）；dispute（P-opbind 深度门）、dispute_book（P-fsane 哨兵 /
深度 / 重复 idx 0）、dispute_claw（深度门）、dispute_bind / dispute_fill（op 形状门）、rollup
（版本门 5）定义变化；`Reveal{Cancel}` 的 ops 叶与灰尘清算是共识变化；快照格式 v9。op 预算：
vault 364、rollup 1016、dispute 1601、dispute_fill 1974、dispute_bind 1960、dispute_book 1801、
dispute_claw 1827、dispute_xframe 1598；rollup 只接受 `assertion_version == 5`。

第 7 轮部署变化：unit id 改为文本哈希、每个 unit 一笔成交、witness 新增 `band:` 叶（共识级，
出块方与 watcher 同时升级）；dispute（P-opbind）、dispute_book（P-fsane idx）、dispute_claw
（ADL 价格）、rollup（版本门）定义变化。op 预算：vault 364、rollup 996、dispute 1575、
dispute_fill 1966、dispute_bind 1956、dispute_book 1712、dispute_claw 1780；rollup 只接受
`assertion_version == 4`。

第 6 轮部署变化：新增 dispute_claw；rollup 新占位与 case。第 6b 轮 op 预算：vault 364、rollup 996、dispute 1383、dispute_fill 1966、dispute_bind 1956、dispute_book 1708、dispute_claw 1706（上限 2000）；rollup 只接受 `assertion_version == 3`。

第 5 轮部署变化：vault 新增 `pperp_total` 与 `perp cap` bounce（vault base 哈希改变，部署
脚本推导）；op 预算 vault 364、rollup 976、dispute 1383、dispute_fill 1959、dispute_bind 1618、
dispute_book 1704。

第 4 轮部署变化：bind AA 带 `VAULT_BASE_HERE` 占位符（R4-A-4 读金库账本），必须在
vault base 地址算出之后再部署（vault base 本来就最先部署）；PERP 供应上限
`PERP_SUPPLY_MAX`（R4-A-6）。op 预算：vault 353、rollup 976、dispute 1383、dispute_fill
1971、dispute_bind 1596、dispute_book 1117（上限 2000，dispute_fill 余量 29）。

### 生命周期（高度 h）

```
pool       {pool:1} → pool_<trigger.address> += 输出-10000（bounce 费之外净额）

submit(h)    h == last_submitted+1 ∧ chain_id='minuend-v2' ∧ 双根 + 六个 44-char
             承诺根 ∧ 组合单元 = header temp_data（`frames_blob` 或
             `packages`+`data_root`，gzip 帧）+ submit；多包时 package 单元先发，
             da_unit 只钉哈希列表
             ∧ 输出 ≥ 10000（仅 bounce 费）∧ pool_<sender> ≥ 1000000000000
             ∧ last_submitted-last_finalized < 50（在途占用）
             → 写全部 <h> 键、da_unit_h=trigger.unit、last_submitted=h；
               活高度重发（h ≤ last_submitted 且 frozen≠2）→ bounce('height taken')；
               欺诈重开的后续高度可自由覆盖；
               prev 必须等于上一高度 state_root（除非上一高度已 frozen=2）

fraud(h)     窗内（submitted_at+3600）任何人打 dispute / dispute_fill：
             deposit | withdraw | escrow(Cancel only) | fill_math | ghost | skip
             | wpin | adr | tip | keep | mirror | mbind | frame | fsane | claw
             （第 2 轮：ghost/skip → dispute_book；wpin/adr/tip/keep/mirror → dispute_bind；
             第 4 轮：mbind → dispute_book，frame → dispute_bind；第 5 轮：fsane → dispute_book；
             第 6 轮：claw → dispute_claw；
             fill_math → dispute_fill；其余 → dispute。verdict 后挑战者得 floor(罚没/5)）
             （#47：p: op 为 p:{acct}:{market}:{side}:{price}:{qty}:{isolated}:{margin}:{tif}:{typ}；
             fill_math 的 kind 0/1 taker 腿按 op 重算 taker_post 与挂单余额；kind 2/3 只在
             L: 单元的订单簿路径、对手方 post 抵押 > 0、caller ≠ maker 时判定；skip 判每个
             unit 的第一笔 fill（idx 0）；gov D:/W: 对 pre_absent 账户出现 post 叶即欺诈）
             当前 P-omit 不可用：force 只存时间戳，不能证明 unit 存在，
             omit case 恒 bounce('no fraud')
             P-escrow 仅用于 Cancel：post collateral 必须精确等于 pre
             collateral + pre-order margin_left；Place escrow 无此证明分支
             验不过 → bounce('no fraud')，高度不动；
             验过 → dispute 付 10000 bytes + {verdict:'fraud',height,challenger}
               → rollup frozen_h=2、清根（含 aa_root）、last_submitted = min(ls, h)
                 （#47 A1：只会下调到失败高度，绝不上调；其上的高度作废、可被前向提交覆盖；
                 frozen 重提只允许 h == last_submitted）、
                 pool_<operator> 扣 min(500000000000, pool)、
                 slash_reward_<challenger> += 实际扣款

finalize(h)  !frozen ∧ h == last_finalized+1 ∧ prev_<h>==state_root_{h-1}
             ∧ now ≥ submitted_at_h+3600（escape_finalize 用 604800）
             → 先复核 sha256(aa_forest_h,'hex')==aa_root_h，再 last_finalized=h；
             reward += 20000（无 sbond 记账）

claim        'reward'|'sbond'|'slash' 按旧键支付；'pool' 仅链空闲
             （last_submitted==last_finalized 且 frozen_<last_submitted>≠2）可取，全额支付并清零

withdraw     vault（参数化实例，rollup = params.rollup）：
             adr:{trigger.address}:{account} 与 acct:{account}:{col}:{perp}:{W}
             都必须在 wit_root_<h>（h ∈ (lf−32, lf]）中；amount + wd_<account> ≤ W
             → 支付抵押品并累加 wd_<account>（PERP 领取一律 bounce
             'perp claim needs burn'，见 MECHANISMS 10.5 / #12）

force(id)    rollup：{force, unit_id 64hex} → inbox_<id>=timestamp；
             仅记录时间戳；当前没有可执行的非成员挑战来证明漏收
```

`temp_data` 帧是 UTF-8 JSON 行：包内多帧以 LF 分隔；第一个 package 不加
包前缀，后续 package 以一个 LF 开头；所有新 package 都不以 LF 结尾。
`data_root` 始终是 SHA-256(按顺序直接拼接的原始 gunzip package 字节)，不含
gzip wrapper。watcher 必须先按这些未修改字节校验 root；对旧 producer 的多包
数据，只能在解析副本中为缺失的包间边界补 LF，不能重算/改写 `data_root`。
因此旧 writer → 新 watcher 与新 writer → 旧 `split("\\n")` watcher 均可读，
无需 framing-version 字段或强制 producer-first 升级；单包 inline root 也须校验。

**没有 lock，没有 `{challenge:1}`，没有应诉。** 揭发必须算对那一笔；
诚实根杀不掉。常备池是资本门槛，不是许可名单。

关键安全性质：

- **余额权威是 proof 叶子**——operator 腐化也改不了提款上限。
- **`adr:{trigger.address}:{account}` 绑定**：只能为自己绑定的账户证明；同一账户的第二个地址被 P-adr 拒绝，`wd_` 按账户累计（R2-A-8）。
- **无 owner key / 无原地升级**：若部署新 AA，用户需自行通过 finalized-root 证明
  从旧 vault 提款再存入新部署；当前没有自动迁移工具。
- 常量注释映射 Rust 权威定义（CHAIN_ID / POOL_MIN / POOL_MAX_INFLIGHT /
  `SUBMIT_BOND_NET`〔历史命名，现为常备池下限而非逐高度债券〕 /
  CHALLENGE_SECS / ESCAPE_STALL_SECS），避免双源漂移。

Oscript 实现细节（踩过的坑）：

- `sha256()` 默认输出 **base64**，必须显式 `'hex'` 才能与 Rust hex 域一致；
- `reduce(arr, count, f, init)` 回调签名是 `(acc, index, value)` 三元；
- count 必须是静态字面量（复杂度 = count × 回调复杂度），故证明深度上限 16
  （覆盖 2^16 账户），超出直接 bounce；
- init 里禁止写 state var，只能通过 state message 落盘。

## 5. 威胁模型小结

| 攻击 | 防线 |
|---|---|
| 伪造成交/假根 | 双 Merkle 根 + validate_against 重放 + 一枪谓词（含 fill_math/ghost/skip） |
| 偷 AA 资金 | 提款只认 finalized 森林的 Merkle 证明；leaf 绑定地址；wd_/wp_ 防重放 |
| 付钱杀根 | 已删除：challenge 无 case；假证明 bounce `no fraud` |
| 审查 | rollup inbox `{force}` 钉时间戳；P-omit 按 #23 禁用（force 无法证明单元存在，恒 bounce） |
| 存款自铸 / 抢跑 | deposits_allowed + deposit_backing(amount, payer, account) + 逐锚点 evidence 校验（payload_hash、指定账户）+ evidence 绑定 `MINUEND_VAULT_AA` |
| 溢出 DoS / 签名延展 / 乱序 | 入口 checked-mul / verify_strict / orphan 缓冲 |

## 6. 已知局限

见 README「局限与主网就绪度」。付钱否决已删；仍未链上验：`fill_math` 对
负的预期 collateral 只会 bounce `no fraud`，ADL kind-2 没有 fill-proof 分支，
仓位 entry 比较允许 ±1 最小单位容差；collateral 恒等式容差 ±6（第 3 轮 R3-A-3：
每条成交腿最多 6 个最小单位错记不可挑战，换取在 Oscript 15 位精度下仍能判欺诈）；提供的充值 joint 也不证明 Obyte inclusion/
stability。P-escrow 只验证 Cancel 退款的精确变化，不覆盖 Place escrow。`temp_data`
正文保留 24h。第 4 轮：P-frame 只覆盖 `c:`/`d:`/`w:`/`D:`/`W:`；P-mbind 对同位数 > 15 位的
剩余量不比较；R4-A-5 在 ≥ 1e14 量级跳过若干数值比较；watcher 在金库记录未知时不构造依赖
它的 P-adr。第 5 轮：两条成交腿的 claw 金额没有互相绑定（CRITICAL，仍可用自己的账户
造钱，需新 AA）；ADL 价格不绑定 mark；≥ 1e14 仍跳过仓位比较；`x:` taker 只判 collateral
上限；金库 PERP 上限先到先得、烧毁的 PERP 仍占额度、触顶 bounce 未在 devnet 测试。默认执行序 UnitId 字典序
（v2 commit-reveal 高度 0 生效）；报价质量受债券多数约束。
主网部署前需正式 oscript 审计。「纯永续 → 图灵完备」升级路径见
[ROLLUP-UPGRADE.md](ROLLUP-UPGRADE.md)。

## 7. 治理动机：PERP

把白名单换成资产。协议最初的三处中心化硬编码——市场准入
（`allowed_markets`）、预言机来源（`trusted_oracles`）、风险费率——分别由
PERP 的三个机制接管：

- **无许可市场上架**：上架成本 = 烧毁 10 000 PERP。烧毁而非收费，意味着
  上架费不流向任何受益人（没有"收钱上架"的寻租空间），而是让全体持有者
  的流通量通缩；同时给垃圾市场一个真实价格门槛。
- **债券注册制预言机**：报价资格 = 质押 50 000 PERP 债券。债券是皮肤在
  游戏里的押金——为未来的罚没路径预留；中位数聚合让单点操纵无效，腐化
  必须收买按债券计的多数。
- **链上提案投票**：参数修改（IM/MM/费率/Delist）走 CreateProposal → Vote →
  FinalizeProposal，全部是普通签名 unit、按 DAG 确定性线性化执行——治理
  不需要新的共识机制，重放即审计。投票权重取投票执行时刻的余额（MVP
  语义，避免存整份快照映射）；quorum 分母用创建时的 `supply_at_create`
  快照，保证通过判定与重放时刻的流通量无关。

记账上 PERP 走侧链镜像（复用 vault AA 与双 Merkle 树，叶子各加一段 perp
字段），烧毁只在镜像账本进行——对应真实 PERP 永久滞留 AA，协议整体对
PERP 超抵押。精确规则见 [MECHANISMS.md](MECHANISMS.md) §15。

> **Watcher：** `crates/minuend-watch` 离线重放 `da_unit_<h>` 并可组
> `proof.json`。当前 `post_challenge.js` 仍是本地 aa-testkit CLI，未接入生产
> hub 提交路径；不能据此声称生产环境会自动发挑战。#37 的自动提交项仍未解决，
> 本 PR 也不修改该脚本。
