# MINUEND 机制详解（Mechanism Reference）

本文是 MINUEND 所有运行机制的完整参考，面向需要理解或复现每一层内部行为
的读者。概览见 [README](../README.md)；设计动机叙事版见
[PROTOCOL.md](PROTOCOL.md)。本文按"机制 → 精确规则 → 边界情况"逐层展开，
所有数字均可在 `crates/minuend-types/src/lib.rs` 找到对应常量。

---

## 目录

1. [账本与定值体系](#1-账本与定值体系)
2. [DAG 与单元](#2-dag-与单元)
3. [订单簿撮合](#3-订单簿撮合)
4. [账户与风险引擎](#4-账户与风险引擎)
5. [清算、keeper 与保险基金](#5-清算keeper-与保险基金)
6. [手续费与资金费率](#6-手续费与资金费率)
7. [预言机与 mark 价格](#7-预言机与-mark-价格)
8. [批次与结算验证](#8-批次与结算验证)
9. [双 Merkle 树](#9-double-merkle-树)
10. [结算 AA 状态机](#10-结算-aa-状态机chain_idminuend-v2)
11. [Witness 树与谓词承诺](#11-witness-树与谓词承诺)
12. [多 operator 手续费竞速](#12-multi-operator-手续费竞速)
13. [Optimistic / Final 状态提升](#13-optimistic--final-状态提升)
14. [威胁模型对照表](#14-威胁模型对照表)
15. [明确的已知边界](#15-明确的已知边界)
16. [PERP 治理](#16-perp-治理)

---

## 1. 账本与定值体系

### 1.1 三种数量纲

| 类型 | 底层 | 缩放 | 例子 |
|---|---|---|---|
| `Price` | i64 | 1e8 | 可为负（穿仓/归零附近定价）；正数 canonical 字节与 u64 时代逐字节相同 |
| `Qty` | u64 | 1e8 | 1 BTC = `100_000_000` |
| `Usd` | i128 | 1e6 | $1 = `1_000_000`（微美元） |

全程整数运算，无浮点。名义额：

```
notional_usd(qty, price) =
    i128(qty) × i128(price) / PRICE_SCALE × USD_SCALE / QTY_SCALE
```

例：1 BTC @ $100,000 → `1e8 × 1e13 / 1e8 × 1e6 / 1e8 = 1e11`（= $100,000）。

### 1.2 标识符推导

| 标识 | 推导 |
|---|---|
| `AccountId` | `sha256(ed25519 公钥)`，32 字节 |
| `OrderId` | `sha256(account32 ‖ market_u32le ‖ client_seq_u64le)` |
| `UnitId` | `sha256(canonical_bytes)`，canonical 前缀为 ASCII `"ODX1"` |
| 清算单 id | `sha256(b"liq" ‖ unit_id_32)` |

### 1.3 入口溢出防护（DoS 防线）

place() 在任何算术前拒绝：

```
qty > i64::MAX                    → Risk（仓位以 i64 存储）
price·qty 溢出 i128               → Risk（名义额计算前置校验）
market 不存在或已 delisted       → Risk（无许可市场，见 §16）
client_seq ≠ last+1               → DuplicateClientSeq
```

### 1.4 client_seq 连续性

每账户的 Place 携带严格递增 client_seq（首笔必须 = 1）。作用：订单幂等
（重复 seq 被拒）、重放安全（无法重发历史订单）、缺口检测（跳号即丢单）。
client_seq 是账户级全局计数（跨市场），非每市场独立。

---

## 2. DAG 与单元

### 2.1 单元结构

```rust
Unit {
    parents: Vec<UnitId>,   // 1..=2 个，升序、去重
    op: Op,                 // 业务操作
    pubkey: [u8; 32],       // ed25519 公钥
    sig: [u8; 64],          // 对 UnitId 的签名
}
```

操作类型与 canonical 编码 tag：

| op | tag | 字段序 |
|---|---|---|
| Place | 1 | account, market_le4, side_u8, typ_u8, tif_u8, price_le8, qty_le8, client_seq_le8, isolated_u8（0/1）, margin_le8 |
| Cancel | 2 | account, order_id |
| Deposit | 3 | account, amount_le16, aa_unit_32 |
| Withdraw | 4 | account, amount_le16, nonce_le8 |
| ReportPrice | 6 | oracle, market_le4, price_le8 |
| Liquidate | 7 | caller, target, market_le4 |
| GovDeposit | 8 | account, amount_le16, aa_unit_32 |
| GovWithdraw | 9 | account, amount_le16, nonce_le8 |
| CreateMarket | 10 | creator, symbol16, tick_size_le8, im_bps_le8, mm_bps_le8, taker_fee_bps_le8, keeper_reward_bps_le8, spot_only_u8（0/1）, funding_rate_u8（0/1）, usd_per_unit_le8, funding_cap_bps_le8, min_price_le8, max_price_le8 |
| CreateProposal | 11 | creator, market_le4, key_u8（ParamKey）, value_le8 |
| Vote | 12 | voter, proposal_id_le8, approve_u8（0/1） |
| FinalizeProposal | 13 | caller, proposal_id_le8 |
后续轮次追加的 v2 操作使用新的 canonical 前缀 `ODX2`（与上表 `ODX1`
区分）：StakeOracle(tag 14)、UnstakeOracle(15)、SlashOracle(16)、
UpdateExternalPrice(17，外部喂价锚，§6.2 末)、Commit(18)/Reveal(19)
（v2 commit-reveal 排序，§2.5）。
canonical 尾部追加 pubkey。签名验证用 ed25519 **verify_strict**：
拒绝可延展签名（非规范 s 值、小阶分量）。

### 2.2 身份绑定

每个 op 的关键字段必须与签名者一致：

- Place/Cancel/Deposit/Withdraw：account == sha256(pubkey)
- Liquidate：caller == sha256(pubkey) —— keeper 身份密码学绑定，
  自我清算在验证层即被拒（caller == target → BadAccount）
- ReportPrice/GovDeposit/GovWithdraw/CreateMarket/CreateProposal/Vote/
  FinalizeProposal：首字段（oracle/account/creator/voter/caller）
  == sha256(pubkey)

### 2.3 插入与乱序恢复

```
insert(unit):
  EmptyParents / TooManyParents(>2) / BadParents(未排序或重复) → 拒绝
  UnitId 已存在            → Duplicate
  存在未知父单元:
    首次见到               → 写入 orphan 缓冲，返回 MissingParent
    已在缓冲中             → 返回 Ok(id)（幂等）
  全部父母已知             → link 进 DAG，进 pending 集
```

orphan 缓冲容量 4096。驱逐按**盐化序**执行：对缓冲单元取
`argmin(sha256(salt ‖ unit_id))`，其中
`salt = sha256(ORDERING_SALT_DOMAIN ‖ 最后最终化根 ‖ epoch_le)`，
`epoch = height / ORDERING_EPOCH_UNITS(512)`——引擎在 `note_finalized`
时轮换盐（`Dag::set_eviction_salt`），同 epoch 内稳定、跨 epoch 轮换。
同一 id 的重复重试若携带不同 canonical 字节，返回
`DagError::RetryMismatch`；Deposit/GovDeposit 的 Obyte 地址超过
`MAX_ADDR_LEN = 128` 字符时，在任何缓冲/验签之前即拒绝
（`DagError::AddrTooLong`）。mark_executed 时做不动点扫描：所有"父母已
全部已知"的孤儿链式解锁。残余边界：各副本观测 finalize 的时刻不同，
收敛前可能驱逐不同的孤儿——DA 层自愈：temp_data 全量重放可确定性重建
缺失单元，WantUnits gossip（`crates/minuend-gossip`，§2.6）可按需向同伴
索取。

### 2.4 确定性线性化（去盐）

`Dag::ready_linearized()`：收集 pending 中父母均已执行的单元，按
`unit_id` 字典序升序返回（审计修复后已**去盐**——盐不再参与执行序，
仅用于 §2.3 的孤儿驱逐；原因：观测 finalize 时刻不同的副本会派生不同
排序盐而互不认同执行序，盐化执行序待 finalize 批内确定性设计落地后
回归）。这是唯一公开全序——任何副本对同一 pending 集算出同一执行
顺序，无需通信。该排序即撮合"价格时间优先"中的时间。

### 2.5 v2 commit-reveal 排序（additive，高度 0 生效；用户选择使用）

默认排序仍可被"签名多个候选挑最小 id"磨队（MEV）。v2 追加两条操作：

- **Commit(tag 18)** `{account, commit, ttl_height}`：提交
  `reveal_commit_hash = sha256(inner_op_bytes ‖ salt)`，不含内容 MEV；
  每账户同时存活的未揭示 commit 上限 `MAX_PENDING_COMMITS_PER_ACCOUNT
  = 8`，过期期限 `COMMIT_TTL_HEIGHTS = 16` 个高度（~32 s），meta 叶承诺
  全部 pending commitments（§9.1）。
- **Reveal(tag 19)** `{account, commit_ref, op, salt}`：必须引用自己的
  Commit 单元为父，重算哈希一致后才执行内层 op；TTL 过期未揭示的
  commit 作废并剪枝。

与确定性字典序叠加：Commit 阶段外界看不到 op 内容，揭示后按既有全序
执行。`COMMIT_REVEAL_ACTIVATION_HEIGHT = 0`，因此该路径自高度 0 可用；
用户仍需主动提交 Commit/Reveal 才会使用它。

### 2.6 WantUnits gossip（纯 P2P 层）

`crates/minuend-gossip` 实现 doc 04 §2.4 的按需孤儿同步：节点观测到缺失
父单元后以 `WANT_FANOUT` 扇出 WantUnits（每 (peer, id) 去抖
`WANT_DEBOUNCE_MS = 500`，单请求 ≤ 64 个 id）；收到请求的一方从 DAG 与
orphan 缓冲两侧服务，单响应 ≤ 64 个单元且限频。本层不进共识、不影响
执行确定性，传输载体按 doc OQ5 留待接线。

---

## 3. 订单簿撮合

### 3.1 数据结构

```
bids: BTreeMap<Reverse<Price>, VecDeque<OrderId>>   # Reverse 使最高价居首
asks: BTreeMap<Price, VecDeque<OrderId>>
orders: HashMap<OrderId, Order>                      # O(1) 查询/撤单
bid_qty / ask_qty: BTreeMap<..., Qty>                # level 可见量缓存
```

### 3.2 撮合循环规则

```
while taker.remaining > 0:
  head = 对手方向队列头（taker 为 Bid → 取 ask 头；反之 bid 头）
  无对手头 → break

  crosses:
    Limit Bid: maker_price ≤ order.price
    Limit Ask: maker_price ≥ order.price
    Market:    无条件

  maker.account == taker.account:
    若策略为 Reject 且 maker.margin_left > 0 → 拒绝 incoming Place，不产生成交
    否则撤掉 maker；若其有托管则退回；继续匹配下一单
  否则：
    fill_qty = min(taker.remaining, maker.remaining)
    双方 remaining -= fill_qty；可见量缓存 -= fill_qty（maker level）
    记录 Fill（成交价 = maker_price）
    maker_done → orders.remove(maker_id); pop_head(maker 自己所在侧)
```

Place 对带托管的自家 maker 使用 Reject，避免同单元退款现金腿无法被填充谓词建模；
无托管 cross maker 使用 cancel-maker-continue。Liquidate 等其他撮合调用默认
cancel-maker-continue。TIF：GTC Limit 余量回挂队尾（缓存 += remaining）；IOC/Market 余量丢弃。

### 3.3 可见量缓存不变量

任意时刻 `bid_qty[p] == Σ remaining(bids[p] 中活单)`。维护点：
挂单 += remaining；成交 −= fill_qty（maker 侧）；撤单（任意位置）
−= remaining。非队首撤单留 ghost id 在 deque 中，next_*_head 匹配时
惰性弹出——O(1) 撤单且深度始终正确。best_bid/best_ask 读缓存首元素：
O(log depth)。

### 3.4 价格时间优先的正确含义

"时间"由 §2.4 确定性线性化赋予：同价位先后就是 unit_id 排序中先执行者。
跨副本永远一致。

---

## 4. 账户与风险引擎

### 4.1 成交应用（apply_fill）

每笔成交同时更新 taker/maker 两腿：

- 开仓/加仓（旧仓零或同向）：VWAP 入场价
  entry' = (|pos|·entry + qty·price) / (|pos|+qty)，u128 中间量
- 平仓/反手：实现 PnL
  多头 pnl = close × (exit − entry)/PRICE_SCALE × USD_SCALE/QTY_SCALE；
  空头符号翻转。PnL 即时结算进 collateral（§4.3）；反手余量按成交价开新仓
- 仓位数量 checked_add（防累计溢出 → Overflow）

### 4.2 风险快照

```
upnl   = Σ signed_notional(qty, mark) − signed_notional(qty, entry)
mm     = Σ bps(|qty·mark|, market.mm_bps)    # 创世默认 500
im     = Σ bps(|qty·mark|, market.im_bps)    # 创世默认 1000
equity = collateral + upnl               # PnL 已结算进 collateral
liquidatable : mm>0 ∧ equity×10000 ≤ mm×10500   # ≤1.05
reduce_only  : has_unmarked ∨ (mm>0 ∧ equity×10000 ≤ mm×12000)  # ≤1.20
```
IM/MM 为**每市场参数**（创世市场默认 500/1000 bps，新市场随 CreateMarket
提交，§16.2；快照按仓位所在市场取 `im_bps`/`mm_bps`，市场不在表中时回退
全局默认）。

无 mark 仓位：不计入 upnl/mm/im 且强制 reduce_only。否则 mark=0 给多头
记全额虚亏（可提光）、给空头记全额虚利（可无限加仓）。

### 4.3 PnL 结算模型

平仓瞬间已实现 PnL 进入 collateral：collateral += pnl（checked）；
realized_pnl 仅作统计累加。效果：赢利者立刻可提取全部利润；提款证明
叶子（只承诺 collateral）反映真实偿付能力。

### 4.4 提款

debit(amount)：amount>0；collateral 足额；debit 后快照落入 reduce-only
带则回滚报 Insufficient。重复 nonce 返回 DuplicateNonce。

引擎侧 withdrawals 映射（防重复 nonce 的提款记录）容量上限
65 536 条目，防止无界状态增长。

### 4.5 逐仓保证金（per-order isolated margin）

`Place { isolated, margin }` 携带模式与保证金金额（USD_SCALE），无新
Op；Order/Position 各带 `isolated` 标志。跨仓单 `margin` 必须为 0。

- **模式唯一**：pos_mode（有仓取仓）＞ order_mode（有挂单取首张），
  与订单 mode 不符 → Risk。同一市场绝不混仓。
- **开仓门**（isolated）：`margin ≥ max(extra_im, 1)`、`margin ≤
  collateral`、`equity − margin ≥ im + resting`；无 MIN_OPEN_EQUITY
  （margin 下限即其等价物）。逐仓纯减仓带 margin → Risk。
- **`resting` 口径**（`resting_open_im`，跨/逐仓共用）：只对**真正开仓
  的数量**计价——bids 先减空头、asks 先减多头，超出可减量的部分才
  按该侧加权单价 × `im_bps` 预留；每市场取 `max(bid_im, ask_im)` 后跨
  市场累加。整侧名义额计价会把纯减仓挂单也按全额 IM 拒掉，已修
  （#37-19）。逐仓挂单不计入（其保证金在 place 时已离开 collateral，
  再计即双重预留）。
- **托管**：place 时 `collateral -= margin`；每笔成交按
  `post = fill ≥ remaining_before ? margin_left : margin_left·fill/
  remaining_before`（floor，末笔吃余数）记入
  `isolated_margin[market]` 桶；撤单、未驻留余量退回 collateral。
  自成交（STP）：cross 挂单（`margin_left = 0`）撤 maker 续拍；带托管的
  自家挂单直接拒单（place 路径 `SelfTrade::Reject`）——撤单退款是同一
  单元内的现金腿，填充谓词的精确恒等式无法建模。守恒：
  `collateral + Σ桶 + Σlive margin_left` 只经存提/PnL 变动。
- **平仓释放**：`release = 桶·close/old`（全平取整桶）先入
  collateral，再结算已实现 PnL——桶永不为负；PnL 超桶的缺口落
  collateral 后仍可能为负。逐仓隔离是开仓与风险判定边界，不是坏账担保：
  普通成交随后仅按 §5.3 从非保险对手方可用正抵押有限 clawback；未覆盖部分
  保持负抵押，保险不补。
  产生开仓量的成交 post 进桶；纯减仓 post 直接回 collateral。
- **风险隔离**：`snapshot` 跳过 `isolated` 仓位（跨仓 equity/mm/im
  看不见它）；`isolated_risk(market)` 独立判定：equity = 桶 + uPnL，
  mark 缺失 → reduce_only 且 equity = 桶。清算入口按目标仓位模式
  分叉（逐仓 → isolated_risk，跨仓 → snapshot）；离簿资金费清算的
  target_equity、ADL 排序分母同样分叉。
- **提款**：debit 只看跨仓快照；桶不属于 collateral，提现碰不到它。

---

## 5. 清算、keeper 与保险基金

### 5.1 清算流程

`Place` 成交后会立即复核成交双方；仍可清算的非保险账户可能在同一单元内进入
清算。嵌套清算出错不会回滚已经应用的用户成交，也不会自动重试。

keeper 发起的 `Liquidate { caller, target, market }` 由 `caller` 签名；
`caller == target`、保险账户作为 caller/target、无仓位或目标不满足清算条件
均拒绝。普通市场先对订单簿提交平仓方向的 Market IOC；若目标仍可清算，剩余
数量再以 mark 价 ADL 给反向持仓账户。ADL 候选排除目标和保险账户，按仓位
绝对值降序、`AccountId` 升序打破平局；对手持仓不足时，未平数量留在目标账户，
不会由保险基金接盘。

`funding_rate` 市场不走订单簿：按新鲜外部指数平仓，缺失时回退到非零 mark；
两者都不可用则不执行清算。该路径随后对反向持仓做 ADL；若目标仍有负权益，
本次 ADL 对手方产生的正收益按比例承担剩余缺口，扣款不超过本次正收益，仍
未覆盖的部分留在目标账户。保险基金不补差额。

### 5.2 keeper 奖励

奖励率是每市场参数（创世市场为 100 bps，§16.2）。普通市场以本次清算产生的
各笔成交名义额计算；资金费率市场按 multiplier notional 计算。奖励仅从被清算方
的正 collateral 扣取，不足时只支付可用余额；目标无正 collateral 时 keeper
拿 0，清算不因此取消。保险基金不为 keeper 奖励出资。

### 5.3 普通成交的有限零和 clawback

普通双非保险方成交应用后，逐方检查 collateral：若一方为负，则
`pay = min(-party.collateral, max(counterparty.collateral, 0))`；双方之间
转移这笔金额，保持零和。

该计算不读 account snapshot equity，只看本次成交后的 collateral。即使对手方
可用余额不足，party 仍可保持负 collateral；缺口不会被打印，也不会记到保险基金。
涉及保险账户的成交不会从保险处 claw，也不会 claw 入保险。

### 5.4 保险基金

创世注入 `INSURANCE_SEED = 10,000 USD`，并接收 taker 手续费（§6.1）；保险
账户仍可作为普通账户参与资金费（§6.2）。但其不承担用户交易坏账或 keeper
奖励，也不作为清算目标或普通 ADL 的对手方。

---

## 6. 手续费与资金费率

### 6.1 Taker 手续费（保险收入腿）

每笔成交后：fee = bps(notional, TAKER_FEE_BPS=5)  # 0.05%
taker.collateral −= fee；insurance.collateral += fee。
走 Account 结算路径自动进入证明叶子承诺的 collateral。
taker fee bps 为**每市场参数**（创世市场默认 5，新市场随 CreateMarket 提交，
§16.2）。

### 6.2 资金费率（多空互付）
有效报告数 ≥ 2 时**每高度至多结算一次**（§7；同高度后续报告跳过，
`last_funding_height` 记该高度，diff == 0 也记）：
index = 该市场全部已质押报价者最新报价的**中位数**（未钳位）
spot  = 钳位后的 marks[market]
diff_bps = clamp((spot−index)×10000/index, ±FUNDING_CAP_BPS=50)
每账户 payment = signed_notional(pos.qty, oracle_a) × diff_bps / 10000
payer.collateral  −= payment（钳在上限 = 可用抵押内）   # 借记钳在可用抵押内
receiver.credit   ≤ Σ 实际借记总额                      # 贷记以总借记封顶

spot > index：正 payment → 多头付，空头收；反向镜像。
守恒语义：付款方借记先按其可用抵押钳住，收款方入账总额不超过实际扣减
总额——严格守恒、不产生负余额，截断残差为亚单位灰尘（设计允许）。
保险基金作为普通账户参与资金费（可持有清算对冲仓位）。±50bps 钳幅防
极端偏差抽干一方。
资金费 index 锚可选接入外部价（doc 06）：`Op::UpdateExternalPrice`
(tag 17) 仅接受 `external_sources` 白名单内的 keeper，且仅在市场资金源
切到 `FundingSourceKind::AggregatedExternal` 后生效。index 取外部环的
TWAP；环空或最新样本超过 `FUNDING_EXTERNAL_MAX_STALENESS = 32` 个高度
即视为过期，逐级回退 债券中位数 TWAP → 即时中位数——喂价死亡不会冻结
资金费。环与白名单、资金源选择器均进 meta 叶承诺（§9.1）。
`spot_only` 市场（§16.2）拒绝一切报价（`ReportPrice` 与
`UpdateExternalPrice` 均以 `NotFound` 驳回），有效报告数恒为 0，
资金费永不触发。

`funding_rate` 市场（§16.2，建时定死）走**外部费率 peg**，与上面的
溢价模式正交（普通 perp 不变）：

- **编码**：簿价从不是裸费率。stored price =
  `FUNDING_PRICE_OFFSET(10^12) + rate_bps × FUNDING_BPS_UNIT(10^4)`，
  恒正、0 bps 可表示，`price == 0` 仍保留"无效/市价单"语义。
- **预言机只写 index**：报告仍过 zero/bond 过滤、写 `oracle_reports`/
  history/`last_index`，但**不写 mark**（无 ±10% 钳位）、不跑溢价块；
  TWAP 环照记（slash 判罚依赖 `oracle_twap` 样本），随后走
  `settle_funding_peg`。
- **fill 写 mark**：按 `usd_per_unit` 计的名义额 ≥ 100 USD 且费率步进合法
  才写 `marks`——首个 mark 以**新鲜外部指数**（`fresh_external_index`，
  环内 `height + FUNDING_EXTERNAL_MAX_STALENESS > height` 的最新非零样本）
  自举，费率差 ≤ 该市场 `funding_cap_bps`；已有 mark 时只允许 ≤
  max(|旧费率|/10, 1) bps 的步进。写入后顺带重评 peg；步进不合法则 mark
  与 peg 均不动。
- **结算**（`settle_funding_peg`）：缺 mark → 不推进；首个观测只 arm
  `last_funding_height`（不要求报告者或外部打印）；此后 `height ≥
  last + FUNDING_PEG_INTERVAL_HEIGHTS(14_400)` **总是**先重 arm，付款只在
  存在新鲜外部打印时发生——无新鲜打印则该窗口不付（时钟照走）。diff =
  `clamp(mark 费率 − 指数费率, ±市场 funding_cap_bps)`，按
  `funding_rate_cash(qty, diff, usd_per_unit)` 两阶段转移（借记钳在非负
  抵押内，严格守恒）；`diff == 0` 仍推进时钟。`UpdateExternalPrice` 在
  funding 市场**跳过** `AggregatedExternal` 选择器（仍需白名单、市场存在、
  `price != 0`、费率 |bps| ≤ 10_000），落环后即评 peg。
- meta 叶承诺 `last_funding_height` 时钟；时钟以高度计，不读墙钟。

### 6.3 dust 说明

整数除法截断产生亚微美元残差，随交易数线性累积，经济上可忽略。
系统性 dust 归集属 Phase 2 卫生项。

---

## 7. 预言机与 mark 价格

### 7.1 mark 的多重防线

| 防线 | 规则 | 目的 |
|---|---|---|
| 名义额门槛 | notional ≥ 100 USD 的成交才有资格动 mark | 灰尘单无法操纵 |
| 偏离帽 | 新价相对旧 mark 偏移 ≤ ±10%（旧价 > 0 时） | 单笔巨价无法跳变 |
| 预言机权威 | 一旦市场有任一有效预言机报价，成交永久失去 mark 定价权 | 撮合层与定价层解耦 |
| 无 index 冻结 | 非零 mark 只有在 `last_index`（报告者指数）非零时才允许成交继续移动 | 无外部锚时成交不能逐步走偏 mark |
| index 带 | oracle 写入的 mark 必须落在 funding index 的 ±10% 带内：带外中位数被拒（保留旧 mark；无 mark 时以 index 自举） | 中位数被腐化也走不出指数锚 |

### 7.2 债券注册制 + 中位数定价

```
Op::ReportPrice { oracle, market, price }        # canonical tag 6
```

无许可注册：任何人向侧链质押 `ORACLE_BOND_PERP = 50_000` PERP 即成为
报价者；债券记入 `oracle_bonds`，无白名单、无审批。退出走
`UnstakeOracle`(tag 15) 的 `ORACLE_UNBOND_HEIGHTS = 256` 高度解锁排队，
期间报价即失效；`SlashOracle`(tag 16) 对 TWAP 连续偏移达标者罚没
（500 bps 偏移 ×3 连续采样双条件，`ORACLE_SLASH_ACTIVATION_HEIGHT = 0`，
自高度 0 可用）。另有两条可罚性门槛
（`apply_slash` 前置）：报告历史不足 `SLASH_TWAP_STREAK` 条、或最近一次
报告距当前高度 > 256（新鲜度），任一成立 → `SlashNotEligible`。
罚没 = 债券 ×
slash_reward_bps **烧毁**、余下归挑战者（`apply_slash`：
`burn = bond × SLASH_REWARD_BPS / 10_000`，`reward = bond − burn`；
默认 5000 bps 下恰好各半，但每市场 `OracleConfig.slash_reward_bps`
一旦被治理改写即分叉）。

规则：

- `price == 0` 或 `(market, oracle)` 无债券的报价被忽略（exec 层前置
  校验，state 层防御性忽略）
- 最新报价存入 `oracle_reports[(market, oracle)]`——每记者每市场一价，
  新报价覆盖旧报价
- 有效报价者集合 = 有债券且有最新报价的账户；对同一市场取全部价格的
  **中位数**：奇数取正中，偶数取较小中间值（确定性，任何副本一致）
- `last_index[market] = 中位数`（未钳位，资金费率 index 用）
- spot 写入 `marks[market]` 先过旧 mark ±10% 帽（首个报价无条件设定；
  帽按旧 mark 量级度量，负 mark 同样可步进），再过 funding index ±10%
  带：带外 → 保留旧 mark，无 mark 则以 index 自举（§7.1）
- 该市场有效报告数 ≥ 2 时，资金费**每高度至多结算一次**（同高度的后续
  报告不再付，`last_funding_height` 记该高度；§6.2）

解锁到期的债券经 unstake 路径回到 `perp_balances`，走与其他 PERP 相同的
双币种 Merkle 证明出金路径（§10.5）。`(market, oracle)` 一旦无债券，
其后续报价自动失效。

### 7.3 残余操纵风险

±10% 帽允许攻击者以每 tick 10% 步进逐渐走偏 mark；中位数要求腐化按
债券计的多数报价者配合。两处步进现在被外部锚收窄：无 `last_index` 时
成交把非零 mark 冻结在首个打印价（§7.1），oracle 写入还必须落在 funding
index ±10% 带内。TWAP 平滑（oracle/funding 双环）与连续偏移罚没
已落地，但合谋多数仍可在两次罚没之间施压；外部多源锚（§6.2 末）需
治理启用后才提供第二意见。

---

## 8. 批次与结算验证

### 8.1 批次切分

operator 从线性化执行流中切出前缀（≤ BATCH_MAX_UNITS=200000 units），
调用 `Batch::from_applied(prev_state, engine, applied)`：

```
applied 为空                    → Empty
applied.len() > 200000           → TooManyUnits
checkpoint.height               = prev.height + 1
prev_state_hash                 = prev.state_root()
engine.state.height ← height    （先推进再取根，meta_leaf 绑定高度）
state_root                      = engine.state.state_root()
aa_root                         = aa_forest_hash(aa_sharded_roots)
wit_root / trace_root / units_root / units_set_root /
ops_root / fills_root / counts_root = obyte_merkle（见 §11）
unit_count / wit_count          = applied.len() / wit_leaves.len()
```

高度进入 meta_leaf ⇒ state_root 跨批次成链：`prev_state_hash` 断链
即重组可见。

### 8.2 temp_data 帧披露

header 只带标量（`chain_id`、height、各根计数、`aa_shard_roots`、
`perp_burned`、`validity_proof_hash`）外加 `frames_blob` XOR
（`packages`+`data_root`）；逐单元数组不再进 header。每个 frame 是一单元
JSON（`u,t,o,c,f?,l?,e?`）：`u` 为该单元 JSON（含签名），`t`/`o`/`c` 为
trace/ops/counts 条目，无成交时省略 `f`，`e` 仅 Deposit/GovDeposit 携带
（按 `aa_unit` 匹配证据），`l` 为该单元叶集（print-only 可省略）。
每包内部的多帧以 LF 分隔；第一个包不加前缀，之后每个包在 gunzip 后以一个
LF 开头；新包都不以 LF 结尾。直接拼接新格式 package 字节后，得到无尾 LF 的
JSON 行流（兼容旧 watcher 的 `split("\\n")`）。cap 按含包前缀的
`get_json_source({"package_blob": b64}).len() <= PACK_SOURCE_CAP` 核算。
`data_root` = hex(sha256(按序拼接**原样 gunzip 后** blob 字节))，gzip wrapper
不计入；JS `zlib.gunzipSync` + 原始 concat 与 Rust 同义。watcher 先校验这个
原始 root，再只在解析副本中为旧 writer 缺失的包间 LF 补分隔符。解析修复不得
改写 root 输入。新 reader 支持旧单包、旧多包及尾 LF 历史包；新 writer 可由旧
`split("\\n")` reader 解析。无需 framing-version 或强制升级次序。
非法 gzip → BindingMismatch；单包 inline 的 `data_root` 同样按原始字节校验。
`l` 保留在线上——`prove.rs` 的 `deposit_proof` 要拿 liar 贴过的叶子对
committed `trace[k]` 开证明，省 `l` 会让一枪谓词开不了。多包时 `packages`
记 package 单元的真实 Obyte unit hash 列表（poster 先发包、拿到 unit 后填，
Rust 打包时只留占位），watcher 按条目 `get_joint` 取包、gunzip 后拼接；
承载该对象的 Obyte 单元之规范 `data_hash`
仍为 `hex(sha256(getJsonSource(header或package对象)))`。充值证据在 frame
`e` 内，复原即拼接各 `e` 字段（无 header `deposit_evidences`）。
空帧集合不是有效批次。不可拆分的单帧仍可能独自超 cap：Rust 在去 `l` 重打后
仍超限时只供 print-only、不可提交；JS `post_batch.js` 在发包前执行同一 source
cap 检查并拒绝超限输入。watcher 在缺失 joints 上 backoff 放弃，绝不误挑战。

意义：

- 数据可用性：任何观察者可在 1 天保留窗口内下载并本地重放
- 重放可定位本地 checkpoint 不一致；不等于每类不一致都有链上谓词可证
- 可链上揭发的范围依赖 §10 谓词覆盖；P-omit 当前恒 bounce，生产自动提交脚本亦未接通

`data_hash`/`data_length` 采用与 ocore 一致的**单一规范形**：
`source = getJsonSource(data)`（递归字典序排序对象键的 minified JSON；
Rust 侧移植于 `minuend_settle::obyte_hash::get_json_source`），
`data_hash = hex(sha256(source))`，`data_length = source 的 UTF-8 字节长`。
数字走**失败即拒**的规范形（`canonical_number`）：可精确表示的整数照印
十进制，但**绝对值 > 2^53 的裸整数直接 Err** —— JS 侧 `JSON.parse` 会把它
舍到最近 f64，Rust 却保留全部比特，两边 hash 输入必分歧；`1.0`（JS 印
`"1"`）、`-0.0`、|x| > 2^53 的非整数、|x| ≥ 1e21（指数形）、|x| < 1e-6 的
非零小数同理。Rust `temp_data_payload` 与 JS 工具链（post_batch.js 的
`obyteDataHash`/`obyteDataLength`）使用同一定义，黄金向量测试对拍同一
嵌套对象得到相同 hash/length。注意区分：**链上 OIP-0007 信封**仍须满足
ocore 校验器（base64 `getBase64Hash(data, true)` / `object_length`），
post_batch.js 把信封两字段直接委托给 ocore，不手写副本。

**DA 绑定 da_bind（第 2 轮 R2-R-1）**：submit 单元必须只含**一条** temp_data
（header）。header 与 `submitData` 都携带 `data_root`、`counts_root` 与

```
da_bind = hex(sha256('minuend-da-v1|' chain_id '|' height '|' prev_state_hash '|'
  state_root '|' aa_root '|' wit_root '|' trace_root '|' units_root '|'
  units_set_root '|' ops_root '|' fills_root '|' counts_root '|' unit_count '|'
  wit_count '|' fill_count '|' assertion_version '|' data_root))
```

整数按十进制、字符串原样（Rust `minuend_settle::da_bind_hash`，JS
`script_helpers.daBindHash`，二者对拍同一测试向量）。rollup 在 submit 时重算
并 bounce `bad da_bind`，并存 `da_bind_h`、`da_hash_h`（temp_data 的
`payload.data_hash`，24h 剥离后仍在）、`data_root_h`、`counts_root_h`。AA 读不到
temp_data 正文，所以"header 字段 == 链上根"不可链上证明；watcher 必须核对
`da_hash_h`、从 header 重算 `da_bind` 并与 `da_bind_h` 比对、核 `data_root_h`，
任一不符即报 DA MISMATCH、该高度不验证、也不用该 header 构造欺诈证明。

### 8.3 validate_against（任何人可审计）

```
chain_id ≠ CHAIN_ID                          → ChainMismatch
header 计数字段 > u32::MAX（fill_count/unit_count/  → RootMismatch（拒绝截断）
  wit_count/assertion_version；原 `as u32` 会静默回绕）
replay 初始 root ≠ prev_root                 → PrevMismatch
批次含 Deposit/GovDeposit → 独立验证充值证据（不再自证）：
  evidences_from_payload(data) 从 temp_data 取回证据，verify_all 以
  (expected_vault, perp_asset) 为绑定逐条复算 unit_hash(joint)，
  并确认 joint 实际向该 vault 地址支付所报金额/资产
                                              → 失败 DepositEvidence
注入 deposits_allowed ← batch 内 Deposit ops 的 aa_unit 集
逐 unit ingest（BadSig 等）                  → Replay
重放事件聚合 fills_root/counts_root 等承诺不符  → RootMismatch
checkpoint.height ≠ replay.height + 1        → RootMismatch（高度绑定）
engine.state.height 推进至 checkpoint.height 后按窗口剪枝
(withdrawals / seen_aa_units / deposits_allowed / commits，以及到期
 oracle unbonding 的债券返还 —— 全部与 `from_applied` 同一 height 同一次
序，剪枝集完全一致)
last_unit 不符 ∨ state_root 不符 ∨ 承诺根不符  → RootMismatch
```

---

## 9. 双 Merkle 树

侧链维护两棵承诺同一组余额的 Merkle 树，原因见 §9.3。

### 9.1 字节域树（state_root）

叶子（排序后两两合并，奇数复制末位，父 = sha256(left‖right)）：

```
account_leaf = sha256("acct" ‖ id32 ‖ collateral_i128le16
                      ‖ realized_i128le16 ‖ pos_count_u32le ‖ positions…
                      ‖ iso_count_u32le ‖ [market_le4 margin_i128le16]*
                      ‖ perp_u128le16)
               # positions = 每仓 [market_le4 qty_le8 entry_le8]
               # iso = 逐仓保证金桶（BTreeMap 序，§4.5）；money 已出
               #   collateral，漏承诺会低估账户资产
               # perp 取自 perp_balances（PERP 治理余额，§16），
               # 与 collateral 并列进入承诺
book_leaf    = sha256(params_91B ‖ b"book" ‖ market_le4 ‖ [price_le8 ‖
               (order_id32 ‖ remaining_le8 ‖ isolated_u8 ‖ margin_left_le8)*]*)
               # params_91B = symbol16 ‖ tick_size_le8 ‖ im_bps_le8
               #   ‖ mm_bps_le8 ‖ taker_fee_bps_le8 ‖ keeper_reward_bps_le8
               #   ‖ delisted_u8 ‖ spot_only_u8 ‖ funding_rate_u8
               #   ‖ usd_per_unit_le8 ‖ funding_cap_bps_le8
               #   ‖ min_price_le8 ‖ max_price_le8（定宽 91 字节）
               #   ——市场参数本身成为被承诺
               #   的共识状态；同时提交每一个价格档与每个活单，
               #   簿深度与参数都逃不过审计
meta_leaf    = sha256(b"meta" ‖ height ‖ seq ‖ last_unit
                      ‖ perp_burned ‖ next_market_id ‖ next_proposal_id
                      ‖ Σ_market(mark, funding_index)
                      ‖ oracle_bonds ‖ oracle_unbonding ‖ oracle_slash_nonce
                      ‖ oracle_twap ‖ funding_twap ‖ funding_index_twap
                      ‖ external_price_ring ‖ external_sources
                      ‖ last_funding_height(资金费 peg 时钟)
                      ‖ commits(commit-reveal) ‖ funding_source
                      ‖ oracle_configs ‖ oracle_reports
                      ‖ oracle_report_history
                      ‖ proposals(含投票集合与权重快照)
                      ‖ perp_balances ‖ perp_supply)
               # 每个 BTreeMap/Set 均带 u32 len 前缀 + 排序迭代写入；
               # TWAP 样本携带 seq；HashSet（voted）排序后提交。
               # 覆盖账户树之外的全部共识状态，重放无法在价格/资金费/
               # 治理/承诺状态上分叉。此为 state_root 格式的破坏性变更。
```
此外，`state_root` 还包含每个已消费充值 anchor 的独立 `dep` 前缀叶；该集合
永久保留且不并入 `meta_leaf`，同一 anchor 再次入账会改变根。

共识破坏记录（主网未发，无迁移）：`CreateMarket` canonical 尾部追加
`spot_only_u8`；book 叶市场参数承诺 57B→58B；`Price` 由 u64 改为 i64
（`tick_size` 同为 i64 但恒为正；`price == 0` 仍拒绝/忽略）。
其后又追加 `funding_rate_u8`（tag 10 尾部）：book 叶参数 58B→59B、
`meta_leaf` 在 `external_sources` 后提交 `last_funding_height`、
snapshot 格式版本 1→2（v1 快照不再加载）。
正数 canonical 字节逐字节不变。
当前 snapshot 格式头为 v5（内容为 bincode 的 `(ChainState, DAG 锚点)` 元组；
v5 对应 `MarketParams` 的 `min_price`/`max_price`），不做跨版本迁移。
`load_latest` 按高度从新到旧尝试，跳过未知版本或不可解码文件；没有可读候选时
返回 `None`。`load_or_genesis` 随后从 genesis 建立状态；gov-nonce WAL 中比快照
更新的 nonce **不并入** `seen_gov_nonces`，而是放在引擎的 `wal_gov_nonces`：
出块路径以 `max(seen_gov_nonces, wal_gov_nonces)` 为水位（不复用本节点已提交的
nonce），验证重放只以已提交的 `seen_gov_nonces` 为水位（被重放的批次正是消费
这些 WAL nonce 的批次）；两种模式都只在提现**成功**后推进水位。调用方须从
genesis（或最近可读快照）重放 finalized 批次。快照只是恢复加速器，不是共识状态。

meta_leaf 绑定 height（from_applied 先把 engine.state.height 推到
checkpoint.height 再取根），使 state_root 跨批次成链：改历史高度必然断链。
meta_leaf **不含** finalized_height——Final 提升只影响本地节点视图，
不属于被承诺的共识状态（见 §12）。

### 9.2 hex 字符串域森林（aa_forest，16 分片）

Oscript 的 `sha256()` 对参数 UTF-8 文本哈希且默认输出 base64——字节域树
无法在 AA 内复算。因此另建同构字符串域承诺，并按 doc 10 的 v2 方案**分片**：
账户按地址划入 16 个 shard，每个 shard 内：

```
leaf = sha256_hex("acct:" + address + ":" + collateral十进制串
                  + ":" + perp十进制串 + ":" + withdrawn十进制串)
node = sha256_hex(left_hex + right_hex)      # 每 shard 深度 ≤ 16
```

每批提交 16 个 shard 根**拼接为一个 1024-hex 字符串 `aa_forest`**
(shard i 位于偏移 i*64)，恰好命中 Oscript `MAX_STATE_VAR_VALUE_LENGTH
= 1024`，submit/lock/失败清扫保持单变量操作。空 shard 提交离线生成的
哨兵根 `hex(sha256("empty:<shard>"))`，零证明无法跨 shard 跳动。Rust
侧构造分片森林与证明；AA 用 `substring(shard*64, 64)` 取出所声明的
shard 根后折叠兄弟路径比对——AA **信任 shard 标签**，但叶子前像保证
可靠性：错报 shard 只会折到错误的根上。经探针 AA 对拍验证 root 逐字节
一致。

> **#47 A2 变更**：aa_forest 仍随每批提交（submit / finalize 时复核
> `sha256(aa_forest,'hex') == aa_root`），但**不再是金库的付款依据**。
> 森林叶子从不公开，任何 dispute 谓词都无法指向一片伪造的森林叶——
> 运营者若在森林里写假余额，没人能证伪。金库改为对已 finalize 高度的
> **witness 根 `wit_root_<h>`**（§11，Obyte 原生 Merkle）付款：该根的每个
> 单元都可经 `trace_root` 被 dispute AA 逐单元挑战。

### 9.3 为什么提款用字符串域承诺（#47 起：witness 树而非森林）

AA 只能做字符串拼接与 sha256——它无法解析 i128 LE、无法遍历仓位数组。
字符串叶子把"证明我有多少钱"压缩成 AA 能完成的一次
`is_valid_merkle_proof`（叶子重算 + 兄弟折叠）。字节域树则继续承担完整
状态承诺（撮合簿、仓位、进度），供 Rust 观察者全量审计。

#47 之前用的是 aa_forest；#47 A2 起改用 witness 树（§11），原因是**可挑战
性**：witness 树的叶子随 trace 逐单元公开、可被 dispute / dispute_fill /
dispute_bind 三个 AA 逐单元判定，而森林叶子没有任何谓词能指向。提款
需要同一个 `wit_root_<lf>` 下的两片叶子：

```
adr:{obyte_address}:{account_hex_64}            # 付款地址 → 账户 绑定
acct:{account_hex_64}:{collateral}:{perp}:{W}   # W = 累计已借记提款
```

`adr:` 叶由引擎在该地址的**第一笔** `d:`/`D:` 存款时写入，一个地址终身
只绑定一个账户、一个账户只有一个地址（`d:`/`D:` op 现在携带地址：
`d:{acct}:{amount}:{addr}`）。其它地址向同一账户存款被引擎拒绝。

---

## 10. 结算 AA 状态机（CHAIN_ID=minuend-v2）

六个 AA 分属三类职责：`minuend_rollup.aa`（主张链）、四个 dispute AA
（`minuend_dispute.aa` 充提与 Cancel-only escrow；P-omit 禁用、`minuend_dispute_fill.aa` 成交、
`minuend_dispute_bind.aa`（#47 A2 新增）W 列 / 地址绑定 / tip / keep / mirror、
`minuend_dispute_book.aa`（第 2 轮新增）P-ghost 与 P-skip）和
`minuend_vault.aa`（托管；第 2 轮起为 base AA + 参数化实例
`{base_aa, params:{rollup}}`）。金库无 owner key，claim 在 rollup。

部署 op 预算（ocore `MAX_OPS = 2000`，`tools/check_aa_complexity.js`，
部署时替换地址后的定义与源文件一致；第 2 轮数值）：vault 276、rollup 976、
dispute 1255、dispute_bind 1094、dispute_book 804、dispute_fill 1919。
dispute_fill 余量 81 ops，新增判定须先腾出预算。第 2 轮的完整变更见 §10.7。

rollup 状态变量（`<h>` 为高度后缀）：

```
last_submitted, last_finalized, dispute_aa, dispute_fill_aa, dispute_bind_aa, dispute_book_aa
submitted_at_h, state_root_h, aa_forest_h(1024 hex), prev_h
wit_root_h, trace_root_h, units_root_h, units_set_root_h
ops_root_h, fills_root_h, counts_root_h, unit_count_h, wit_count_h, fill_count_h
da_unit_h, data_root_h, da_bind_h, da_hash_h      # 第 2 轮 R2-R-1 / I-2
active_bond_h, fee_winner_h, slash_burned          # slash_burned：R2-A-9 锁定的 4/5 罚没
frozen_h ∈ {∅/0=live, 2=failed}
inbox_<unit_id_hex>, inbox_upto_h
pool_<addr>（常备池；提交门 pool>=1e12）
sbond_<addr>, reward_<addr>, slash_reward_<addr>（sbond 仅遗留 claim 路径）
```

时钟：

| 门 | 原点 | 时长 |
|---|---|---|
| 谓词揭发 / finalize | `submitted_at_h` | 3600 s（CHALLENGE_SECS） |
| escape_finalize | `submitted_at_h` | 604800 s |

### 10.1 submit(h) — rollup

前置：`chain_id=='minuend-v2'` ∧ `assertion_version==2`（#47 B8：随本次 AA 重新部署从 1 升到 2）
∧（h == last_submitted+1 全新提交 ∨ frozen_h==2 且 h == last_submitted 原位重提——#47 A1）
∧ 全新提交时 prev == `state_root_{h-1}`（前序高度 fraud-failed 时拒绝，
  不再豁免——失败高度之上的新链必须走重提分支）；重提时 prev 必须等于
  `state_root_{h-1}` 的**当前值**（前序同样失败则 fail-closed，先修低高度）
∧ state_root/prev 64 hex ∧ aa_forest 1024 hex
∧ `aa_root` 64 hex 且 `sha256(aa_forest,'hex') == aa_root`（散列绑定，
  错配 bounce 'bad submit'）
∧ 六个承诺根 44 b64
∧ 组合单元（temp_data 在同一 unit，`da_unit_h=trigger.unit`）
∧ 输出 ≥ 10000（仅 bounce 费）∧ `pool_<sender> >= 1e12`
∧ `last_submitted-last_finalized < 50`（在途占用）
→ 写全部 <h> 键（含 `aa_root_<h>`）+ `inbox_upto_h = timestamp` + last_submitted=h；
  活高度重发（h ≤ last_submitted 且 frozen≠2）→ bounce('height taken')；
  frozen==2 高度原位重提复位 frozen=0。无 lock。

### 10.2 谓词揭发 — dispute / dispute_fill

| 谓词 | AA | 证明什么 |
|---|---|---|
| deposit / withdraw（含 D/W gov） | dispute | op 前后余额算术（含 pre_absent 非成员） |
| escrow（P-escrow） | dispute | 仅 Cancel：post collateral 必须精确等于 pre collateral + 被撤订单 pre-leaf 的 `margin_left`；Place escrow 没有此证明分支 |
| omit | dispute | 当前禁用：force 只记录时间戳，不能证明 unit 存在；该 case 恒 bounce `no fraud` |
| fill_math | dispute_fill | 普通受支持成交的账户/订单身份与 collateral 恒等式（含逐仓 post、释放、PnL、taker fee）；任何负的预期 collateral 都 bounce `no fraud`，不作欺诈判定；仓位 entry 比较容差为 ±1 个最小单位。#47：kind 0/1 taker 腿把 fill 绑定到本 unit 的 `p:` op（账户/市场/方向/数量），链上按 `book.rs` pro-rata 重算 `taker_post`（±1），按 op 的 typ/tif 推出剩余挂单是否留簿及其 `margin_left`，并校验逐仓 bucket；kind 2（ADL）/3（清算）只在 `L:` 单元订单簿路径（taker==target、caller≠maker、target 为 cross、对手方 post 抵押 > 0）上判定，target 腿扣除 keeper 奖励；资金费率场外 ADL 一律 bounce |
| ghost | dispute_book（第 2 轮由 dispute_fill 迁入） | 成交的 maker 订单 id 前缀区间不在 pre_wit（kind 2 / 全零 maker 订单 id 一律 bounce，R2-A-6） |
| skip | dispute_book（第 2 轮由 dispute 迁入） | pre_wit 中存在更优活单未成交（#47 B3：只判 unit 的第一笔 fill，多 fill unit 也可判；B7：taker 自己的 cross 挂单豁免，自己的逐仓托管挂单在 Place 成交（kind 0/1）上不豁免） |
| wpin（P-wpin） | dispute_bind | #47 A2：某账户 `acct:` 叶的 W 列在 unit k 发生变化，但该 unit 的 op 不是**该账户自己的** `w:{acct}:{amount}:{nonce}`；合法结果只有 W1 == W0（含被拒）或 W1 == W0 + amount。新账户用 pre 非成员证明（左右邻叶）代替 pre 叶 |
| adr（P-adr） | dispute_bind | #47 A2：unit k 的 post 树出现 `adr:{A}:{X}`，但 pre 树中没有（左右邻叶非成员证明），且该 unit 的 op 不是携带地址 A 的 `d:{X}:…:{A}:…` / `D:{X}:…:{A}`；或 A 已有的绑定被改指向另一个账户（引擎从不改绑）；第 2 轮（R2-A-8）：账户 X 在 pre 树已有任何 `adrx:{X}:` 成员时出现新绑定也判欺诈 |
| tip（P-tip） | dispute_bind | 第 2 轮 R2-A-1：trace 树下标 `unit_count-1` 的元素（44 字符）≠ `wit_root_h` |
| keep / mirror | dispute_bind | 第 2 轮：`adrx:` 与 `dep:` 叶一旦出现永不消失（keep）；`adr:{A}:{X}` 与 `adrx:{X}:{A}` 必须成对（mirror） |
| deposit（第 2 轮加强） | dispute | R2-A-3：`d:` 入账必须由金库 `dep_<u>` 记录支撑（payer == op 地址、amount ≤ 记录值），pre 树不得已有 `dep:{u}`（重复入账），post 树必须出现 `dep:{u}` |

**"被拒 = 不变"规则（#47 跨 PR）**：被拒的 unit 同样进入批次（每个执行
过的 unit 在 trace 中占一项）。#49 让更多提款/存款被拒（现货储备、nonce
水位、无对应入账/重复入账、地址规则），因此 deposit / withdraw / wpin /
adr 谓词一律把"相关列保持不变"视为诚实结果并 bounce `no fraud`；只有
"既不等于 pre、也不等于 pre ± amount"的第三个值才判欺诈。引擎对不存在
账户的被拒提款不再创建账户（因此 post 中不会凭空出现空叶；若出现
col 0 的空叶也按不变处理）。Rust 观察者 `prove.rs` 同步镜像该规则。

**claw 守卫（#47，dispute_fill 全部 kind）**：成交后某方 fill 阶段 collateral
为负时，引擎把窟窿从**另一方**（赢家）身上扣回（零和，保险基金不动），
扣不完的部分仍为负。仅凭叶子无法还原这一过程，所以：
- 被判定腿的预期 collateral 为负 → 一律 bounce `no fraud`；
- 判定**赢家腿**的 collateral 不符时，必须另附对手方 post `acct:` 叶
  （`cp_acct` + 证明，root == post_wit）且其 collateral **严格为正**——
  对手方若曾为负，claw 之后它只会 ≤ 0，正值即证明本腿未被 claw；
- kind 0/1 的 maker 腿还要求 taker 的 op 是 **cross** Place（逐仓 taker 的
  托管退款落在 claw 之后，叶子无法区分）；
- 否则 bounce `no fraud`（保守：宁漏判，不误判诚实数据）。

公共门：`frozen`/`submitted_at+3600`、stale-root 对比 rollup 变量、
所有成员证明 `.root` 必须等于对应 pre_wit/post_wit/roots。
揭发者实付 `>= 20000` bytes（dispute AA 门槛，含自身 bounce 余量）；
验不过 bounce('no fraud')；验过 → 转发 10000 bytes + data
`{verdict:'fraud', height, challenger}` 给 rollup。
### 10.3 verdict(h) — rollup

`trigger.address ∈ {dispute_aa, dispute_fill_aa, dispute_bind_aa, dispute_book_aa}`
（第 2 轮：`dispute_book_aa` 同样经 `{set_dispute_book:1}` 由 book AA 一次性登记）
（第三个地址经 `{set_dispute_bind:1}` 由 bind AA 自己一次性登记，rollup
硬编码 bind AA 地址、bind AA 不硬编码 rollup，避免 chash 循环） ∧ verdict=='fraud'
∧ 高度 live ∧ 窗内 ∧ challenger 是合法 32 字符地址
→ frozen_h=2、清 state_root/aa_forest/aa_root/active_bond/fee_winner、
  last_submitted = **min(last_submitted, h)**（失败高度钉住，不再回退 h-1——回退会让
  `last_submitted==last_finalized` 误判空闲、池子被提走；#47 A1：也绝不上调——对作废的
  更高高度下 verdict 不能把 ls 抬回去，否则陈旧高度既不能 finalize 也不能重开）、
  `pool_<operator>` 扣 min(5e11, pool)（债务上界=实际罚没额，不再固定记 5e11）、
  slash_reward_<challenger> += floor(实际扣款 / 5)，其余 4/5 永久锁在 rollup
  （`slash_burned` 计数，R2-A-9：防止运营者自己挑战自己把池子"洗"回来）。
### 10.4 finalize / escape_finalize(h) — rollup

`{finalize}`：!frozen ∧ root 在 ∧ h == last_finalized+1
∧ prev_<h> == state_root_{h-1}（stale 高度拒绝 'stale height'：失败高度之上
已提交的旧根在重提/清零后不再能 finalize）
∧ now ≥ submitted_at_h + 3600 → finalize 前复核
`sha256(aa_forest_h,'hex') == aa_root_h`（错配 bounce 'forest hash mismatch'），
然后 last_finalized=h、reward_<fee_winner> += 20000（无 sbond 记账）。
`{escape_finalize}` 同门，窗口阈值 604800，

### 10.5 withdraw — vault

`ROLLUP = params.rollup`（第 2 轮：金库是参数化实例，见 §10.7）；
`$lf = var[ROLLUP]['last_finalized']`；证明高度 `trigger.data.height` 可取
`(lf−32, lf]` 内任一整数（缺省 lf，R2-A-12）；`$wr = var[ROLLUP]['wit_root_'||h]`
（缺失 bounce 'no root'）。#47 A2：不再读 aa_forest。
请求携带 `amount, account(64 hex), collateral, perp, withdrawn, adr_proof,
acct_proof`，两份证明都必须 `root == $wr` 且 `is_valid_merkle_proof` 通过：
`adr:{trigger.address}:{account}`（错 bounce 'bad binding proof'）与
`acct:{account}:{collateral}:{perp}:{withdrawn}`（错 bounce 'bad merkle root'）。
付款人身份由 `adr:` 叶决定，不再由账户字段推出；该绑定与 W 列由
dispute_bind 的 P-adr / P-wpin 逐单元守护。
`amount + wd_<account> <= withdrawn`（第 2 轮 R2-A-8：`wd_` 按**账户**而非地址累计；W=侧链累计借记提款，是唯一的付款依据；
旧 `min(collateral, withdrawn)` 双重计数会永久锁死 W>col 账户）；
一律 `bounce('perp claim needs burn')`（#12：侧链仅 GovWithdraw 减
`perp_balances`，先兑付会双计投票权；PERP 持有者可传 `perp_amount: 0`
只提抵押品）。`{escape_withdraw}` 无对应 case（vault 仅 `deposit` /
`deposit_perp` / `withdraw`），按未匹配触发 bounce。

### 10.6 pool / force / claim — rollup

`{pool:1}` 净流入（减 10000 bounce 费）累加 `pool_<sender>`，不足 10000
bounce `need pool`。`{force, unit_id 64hex}` ≥10000 bytes →
`inbox_<id>=timestamp`（重复 bounce `already forced`）。
claim 四态：`reward|sbond|slash` 按旧键支付；`pool` 仅链空闲
（`last_submitted==last_finalized` **且** frozen_<last_submitted>≠2，
否则 bounce `pool busy`）可取，全额支付并清零。

### 10.7 第 2 轮（#47 R2）变更汇总

**AA 侧（6 个 AA 全部重新部署）**

- **dispute_book AA**：P-ghost / P-skip 拆到 `minuend_dispute_book.aa`
  （ops 预算）。rollup 占位 `DISPUTE_BOOK_AA_HERE`、变量 `dispute_book_aa`、
  绑定 `{bind_book:1, rollup}`。watcher 用 `--dispute-book <addr>` 指定其地址
  （缺省时 live 发帖脚本读 rollup 的 `dispute_book_aa` 变量）。
- **金库 base + instance**：`minuend_vault.aa` 是 base AA（不含任何地址），
  实际金库 = `['autonomous agent', {base_aa, params:{rollup}}]`。这样
  `minuend_dispute.aa` 只需硬编码 base 地址（占位 `VAULT_BASE_HERE`），即可用
  `chash160` 推导出某个 rollup 唯一的真金库并读它的账本，不必信任调用方给的地址
  （rollup 不能硬编码金库：金库指向 rollup，会形成 chash 循环）。
- **`dep_` 记录**：金库每笔 `{deposit}` 写 `dep_<trigger.unit> = '{payer}:{amount}'`
  （amount = 输出 − 10000 bounce 费）。
- **`d:` 变为 5 段**：`d:{acct}:{amount}:{addr}:{aa_unit_b64}`，第 5 段即金库
  `dep_` 键里的 unit（标准 base64）。`D:`（PERP）仍是 4 段。
- **Reveal 描述串（R2-E-2）**：`Reveal{inner}` 的 inner 为 Deposit / GovDeposit /
  Withdraw / GovWithdraw 时，`ops_element` 输出 inner 的描述串（`d:`/`D:`/`w:`/`W:`），
  其余仍为 `x:{unit}`。配合执行层 R2-E-1（inner 签名账户必须等于 Reveal 账户），
  P-wpin / P-deposit 对 Reveal 包装的资金操作同样有效。
- **P-wpin 联合判定（R2-A-2）**：自己的 `w:` 被拒 ⇔ W 与 collateral 都不变；
  被接受 ⇔ pre 叶存在且 W+amount、collateral−amount；其他 op 下 W 不变。
- **da_bind（R2-R-1）**：见 §8.2 末尾；rollup 重算并存 `da_bind_h`、
  `da_hash_h`、`data_root_h`、`counts_root_h`，submit 单元只允许一条 temp_data。
  header ≠ 链上根本身仍无法链上证明（真正的 DA 问题），只能由 watcher 检测。
- **罚没 1/5（R2-A-9）**、**金库证明高度窗口 32（R2-A-12）**、
  **`wd_` 按账户（R2-A-8）**、**kind-1 collateral 腿不判（R2-A-7）**：见上文各节。

**执行层（引擎）**

- **R2-E-1**：Reveal 的 inner op 不能是 Commit/Reveal，且签名账户必须等于外层。
- **R2-E-3**：提款后 equity 必须仍覆盖挂单（开仓方向）所需保证金。
- **R2-E-4**：`spot_only` 仓位永不被清算（keeper 与 force-sell 都不行）。
- **R2-E-5 每账户提款上限与最小额**：删除全局 `WITHDRAWALS_CAP`；
  `MAX_PENDING_WITHDRAWALS_PER_ACCOUNT = 64`（2048 高度修剪窗口内仍在表中的条目）；
  `MIN_WITHDRAW_AMOUNT = 1 USD`，小于 1 USD 的正数提款只有在等于全部 collateral
  （清仓）时才允许，否则 `Risk`。
- **R2-E-6**：逐仓 taker 手续费不能通过 claw 转嫁给 maker，也不能吃进 cross 现货储备。
- **R2-E-7**：gov nonce 水位只看已提交状态（生产者 = 验证者）。
- **R2-E-8 现货 / 非现货混用禁令**：cross 现货单要求账户在任何非现货市场
  既无仓位也无挂单；任何非现货单要求账户无 cross 现货仓位或挂单。逐仓现货不受限。
- **R2-E-9/10**：整数宽度加固（i128 累加、`qty == i64::MIN` 拒单、book 价位缓存
  `wrapping_add_signed`）。
- **R2-E-11**：资金费率场外清算与 Reveal 全有或全无。
- **R2-A-11（本轮整合修复）**：资金费率场外清算的 keeper 奖励只按 ADL 实际
  平掉的数量计算；一个对手方都没有（什么也没平）时整个 Liquidate 被拒
  （`NotLiquidatable`、状态回滚、不付奖励）。
- **R2-R-3**：超出编码范围的金额在 ingest 即拒（`AmountOutOfRange`）；
  `Batch::frames()` 返回 `Result`，不再 panic。

**重放 / DAG / watcher**

- **PARENT_WINDOW（R2-R-6/7，共识规则）**：一个 unit 只有在它的每个父单元都位于
  最近 `PARENT_WINDOW = 2 × BATCH_MAX_UNITS` 个已执行单元之内时才执行（genesis 视为
  第一个单元之前的虚拟单元）。该窗口与快照持久化的锚点环
  `DAG_ANCHOR_LIMIT` 相同，因此从快照恢复的节点与从 genesis 运行的节点对每个
  unit 的判断完全一致；过旧父单元、窗口外重发的旧单元都被所有节点拒绝。
- **快照版本**：`SNAPSHOT_FORMAT_VERSION = 6`（v6 = `ChainState.aa_address_owners`，
  #47 A2 引入但漏 bump，R2-R-14 补上），并新增布局指纹测试
  `layout_fingerprint_is_pinned_to_format_version`：布局一变测试即失败，必须同时
  bump 版本并重新钉指纹。旧 v5 快照不可读，需从 genesis / 已发布批次重放。
- **帧逐字节透传（R2-R-4）**：`post_batch.js` 不再 `JSON.parse → stringify` 帧
  （会把 > 2^53 的整数舍入），改由 `frame_stamp.js` 只在 Deposit/GovDeposit 帧
  末尾拼接 `,"e":<evidence>`；`data_root` 覆盖拼接后的字节。
- **watcher**：校验 `da_bind_h / da_hash_h / data_root_h`；live 发帖始终带被监视
  的 `--rollup`，dispute AA 地址取 rollup 自己绑定的变量（R2-R-8）；同一
  `(高度, 谓词)` 不重复付费发帖（R2-R-11）；证明文件私有、不跟随符号链接（R2-R-12）。

## 11. Witness 树与谓词承诺

每批 checkpoint 额外携带（`minuend_settle`）：`wit_root`（执行完最后单元的
witness 叶根）、`trace_root`（每单元 post wit_root 的 Obyte 原生 Merkle，
按批序）、`units_root` / `units_set_root`（unit_id hex 批序/排序）、
`ops_root`（op 描述串）、`fills_root`（成交描述串 + 尾随长度哨兵，见下）、
`counts_root`（每单元叶数）、`unit_count` / `wit_count` / `fill_count`。

成交描述串（`fills_element`，14 字段）：

```
f:{unit}:{idx}:{taker}:{maker}:{taker_order}:{maker_order}:{market}:{price}:{qty}:{seq}:{side}:{kind}:{taker_post}
```

`taker_post` = 该笔成交占用的逐仓托管份额（USD_SCALE，taker 挂单为 cross
时 0）；fill_math 逐仓恒等式用它 + post `ord` 叶的 `margin_left` 精确核对
taker 抵押。`fills_root` 树 = 成交描述串 + 尾随长度哨兵 `n:{len}`
（`fills_root_elements`）：末笔成交的右邻即该哨兵，fill_math 单笔完备性
只靠右邻证明即可判定，谓词不读任何提交整数。`fill_count` 仍经 submit 存为
`fill_count_h`（rollup 门与提交头使用），但 dispute 路径不再读它；零成交批次
的 `fills_root` 是单叶 `n:0`。当前验证路径只使用带哨兵的新编码，没有旧
`fills_root` 编码选择/回退；用旧编码生成的离线证明材料须按当前实现重建。

witness 叶（`minuend_state::wit_leaves`，排序后 Obyte 原生 Merkle）：

```
acct:{acct_hex}:{collateral}:{perp}:{W}
pos:{acct_hex}:{market}:{qty}:{entry}:{isolated:0|1}:{bucket}
ord:{order_hex}:{market}:{side}:{price}:{seq}:{remaining}:{acct_hex}:{isolated:0|1}:{margin_left}
meta:{market}:{tick}:{im}:{mm}:{taker_fee_bps}:{keeper}:{delisted}:{mark}:{usd_per_unit}:{funding_cap_bps}
adr:{obyte_addr}:{acct_hex}       # #47 A2：地址 → 账户
adrx:{acct_hex}:{obyte_addr}      # 第 2 轮 R2-A-8：账户 → 地址（反向镜像）
dep:{aa_unit_base64}              # 第 2 轮 R2-A-3：已消费的充值锚点（永久）
~:end                             # 第 2 轮 R2-A-5/10：最大哨兵，恒为最后一叶
```

第 2 轮起每棵 witness 树都以 `~:end` 结尾，所以任何"键不存在"都可以用相邻
两叶（或"在最小叶之前"）证明，谓词不再需要"在最大叶之后"分支，也不再读
运营者自报的 `wit_count`。所有位置证明还要求 `index` 为非负整数、邻叶必须含
`:`（内部节点是裸 base64，从而杜绝"节点冒充叶子"），P-tip 元素长度为 44。

这些数组在 frames 内按单元拆开（`t`/`o`/`f`/`c`/`l`），header 不再带它们；
`leaf_trace` 单帧可省略（print-only）。`validate_against` 重放复算全部根。
`is_valid_merkle_proof` 是 ocore 内建（复杂度 1），格式 `{root, siblings, index}`。

## 12. Multi-operator 手续费竞速


多个 operator 并行观察侧链、各自向 AA 提交组合单元（temp_data + submit
同一 unit）。赢家判定利用 Obyte 原生性质：**AA 只被稳定单元触发，触发按
稳定序生效**。因此"最先稳定"天然等价于"AA 最先处理"——height 归属 =
第一笔被 AA 处理的该 height 组合单元；未冻结的后续提交一律
bounce('height taken')（占位门），不产生安慰金（现状无补贴；输家的
60000 bytes 原样退回，仅损失 bounce 费）：

```
submit(h) 竞速:
  if (!active_bond_h): 处理（首交者胜）
  else: bounce('height taken')            # 单候选, 占用窗内无替换
  da_unit_h ← trigger.unit                # 根↔数据绑定
  if (!fee_winner_h): fee_winner_h ← trigger.address   # 首个稳定者赢
```

- 同批一起稳定的平局由 ocore 内建单元排序裁决；Rust 侧
  `pick_stable_winner`（minuend-settle, mci→unit_id 双键）语义一致
- 赢家奖励在 finalize 成功路径累加（失败高度不发放），{claim:"reward"} 提取
- "交易按第一个稳定的填充下一个"由 prev_state_hash 链保证：
  h+1 必须引用赢家的 root_h
- 高度失败回滚后重新竞速（verdict 清空 active_bond_h，组合单元可重新首占；
  fee_winner_h 保持首个处理者不变）

---


## 13. Optimistic / Final 状态提升
引擎事件生命周期：

```
ingest → Applied{status: Optimistic}     # 立即执行、立即成交
   │
   ├─ 批次切出（settle 层）                # 数据准备提交
   ├─ temp_data 上链 + submit             # 数据可用 + 进竞速
   ├─ 谓词揭发（窗内可选）                 # 假账被杀、高度重开
   ├─ finalize（submitted_at+3600 后）     # 根成为提款依据
   └─ 操作者观测到 finalize 事件后调用
      Engine::promote_finalized(unit_ids)
      → 该高度所有 Applied 状态翻转为 ExecStatus::Final
```

- `promote_finalized` 幂等：重复调用返回 0
- 日志状态**不是** state_root 的一部分——提升只影响本地节点视图，
  重放确定性无损。每个节点依据自己观测到的 AA finalize 事件独立推进
- 客户端职责：同时展示 Optimistic（可挑战推翻）与 Final（已成定局）

---

## 14. 威胁模型对照表

| 攻击 | 防线 |
|---|---|
| 伪造成交 / 假根 | 双 Merkle 根 + validate_against 全量重放 + 一枪谓词（含 fill_math/ghost/skip） |
| 偷 AA 资金 | 提款只认 finalized 分片森林的 Merkle 证明；leaf 绑定提款人地址；wd_/wp_ 累计标记防证明重放 |
| 付钱杀根 | 已删除：`{challenge:1}` 无 case；假证明 bounce `no fraud` |
| 审查用户单元 | rollup inbox `{force}` 钉时间戳；P-omit 已按 #23 禁用（force 只钉时间戳、不能证明单元存在，谓词一律 bounce `no fraud`） |
| 存款凭空铸造 | deposits_allowed 白名单 + replay 交叉校验 + evidence 绑定 `MINUEND_VAULT_AA` |

## 15. 明确的已知边界

- `fill_math` 对任何负的预期 collateral 都 bounce `no fraud`，不会判定欺诈；
  ADL kind-2 成交没有链上 fill-proof 分支，仓位 entry 比较另有 ±1 最小单位容差
- P-escrow 只证明 Cancel 退款的精确抵押变化，不覆盖 Place 的托管变动；Place 中
  带托管的自家 maker 会在撮合时拒单，以免产生未建模的同单元退款现金腿
- `temp_data` 正文 24h 后被节点剥除——揭发必须自带那一笔与证明
- `validate_against` 对提供的充值 joint 重算哈希、核收款/金额/资产，并要求
  joint 首作者 = payer = 侧链 `addr`；它不证明 joint 已进入 Obyte DAG 或稳定。
  `MINUEND_VAULT_AA` 为空且带 evidence 会被 `validate_against` 拒
- 预言机为债券注册制（ORACLE_BOND_PERP = 50_000 PERP，无许可）；按债券计
  的多数合谋仍可在两次罚没之间偏置中位数；外部价锚需治理切换 + keeper 喂价
- 大载荷内联 temp_data 会触发 ocore 校验器双回调崩溃：post_batch.js 的
  链上信封字段已直接委托 ocore；devnet E2E 跳过内联揭示
- 无第三方安全审计；各 AA ≤100 复杂度（探针 `check_aa_complexity.js`）
- 独立 watcher 已可组谓词 proof；须以与 poster 分离的密钥部署后，
  互相牵制才算跑通
- 第 2 轮仍未解决：header ↔ 链上根的一致性只能由 watcher 检测（DA 问题，
  需交互式挑战才能链上化）；高度 1 的 unit 0 不可挑战（四个 dispute AA 硬编码
  的 genesis pre 根是 `["empty"]` 的根，而真实 genesis witness 树含 BTC_USD 的
  `meta:` 叶，仅为检测缺口、不会误罚诚实批次）；watcher 重放成本为
  O(units × state)；settle 解码器对其他调用方无长度上限；`post_challenge_live.js`
  未在真实 hub 上联调

---

## 16. PERP 治理

PERP 是 Obyte 原生治理资产，围绕它实现三件事：无许可市场上架、债券
注册制预言机（§7）、链上提案投票改参。资产 ID 在发币前未知，全部以
占位常量落地：Rust 侧 `PERP_ASSET: AssetId = [0u8; 32]`，Oscript/JS 侧
字面量 `'PERP_ASSET_ID_HERE'`，部署脚本加载 .aa 后做字符串替换写入真实
asset id。发币时只需改一个常量并重新部署 AA。

### 16.1 记账模型：侧链镜像

不新建第二个 AA——扩展现有 vault AA 接收 PERP 充值：

- **GovDeposit**（tag 8）：镜像现有 deposit——`seen_aa_units` 去重、
  `deposits_allowed` 白名单（同一集合，replay 时由批次内 GovDeposit ops
  注入交叉校验），入账 `perp_balances[account] += amount`，
  `perp_supply += amount`
- **GovWithdraw**（tag 9）：**独立**的每账户严格递增 nonce 水位线
  `seen_gov_nonces`（`nonce <= watermark` → `DuplicateNonce`，允许跳号），
  不共享 `withdrawals` 表、也不受其 65 536 条目上限约束——水位线按账户数
  有界；无 reduce-only 检查；AA 侧走扩展后的双币种 Merkle 证明提款
  （§10.5，叶子含 perp 字段）

`perp_supply` 是侧链镜像账本的净供应：Σ 充值 − `GovWithdraw` 记账 − 烧毁；
它本身不代表 vault 已能向用户兑付 PERP。当前 vault 对非零 PERP claim
bounce `perp claim needs burn`，因此 GovWithdraw 只更新侧链镜像，不是 Obyte
AA 的 PERP 付款。

**CreateMarket**（tag 10）：任何人可上架，代价是烧毁
`CREATE_MARKET_FEE_PERP = 10_000` PERP 上架费。市场参数随 op 提交
（symbol、tick_size、im_bps、mm_bps、taker_fee_bps、keeper_reward_bps、
`spot_only`、`funding_rate`），
存入 `markets[market_id]`——IM/MM/taker fee/keeper 奖励从全局常量变为
**每市场参数**（§4.2/§5.2/§6.1 相应改为读参数）。除 tick_size 为 0 →
Risk 拒绝外，四个 bps 参数统一过 `risk_params_ok` 谓词（minuend-types，
exec 与治理共用）：任一为 0 或 > 10 000、`im_bps <= mm_bps`、
`mm_bps < 500`、`im_bps > 5000`、`taker_fee_bps > 200`、
`keeper_reward_bps > 500`、`im_bps < 10 × FUNDING_CAP_BPS` 均 Risk；
`spot_only` 市场另走**全额抵押**分支：`im_bps` 必须恰为 10 000
（`mm_bps` 仍须 ≥ 500 且 `im > mm`，`keeper_reward_bps` 仍须 ≤ 500，
`funding_rate` 必须为 false；只有 IM 规则与普通市场不同）。
tick 检查（`tick_size ≤ 0` → Risk）先于一切 `% tick_size` 运算，零/负 tick
不会再让节点 panic。
CreateProposal 对非 Delist 键先按 finalize 同样方式预演参数更新，结果不
过谓词即 Risk（提案表不写入）；FinalizePropose 落盘前同样复检——通过但
非法的提案是 no-op（不写字段，提案仍被消耗）。
簿不预建，沿用 `book_mut` 惰性创建。

`spot_only` 建时定死：无 `ParamKey` 可翻转。`true` 的市场为纯合约/meme
市场——拒收一切报价（双通道 `NotFound`，见 §6.2）、永无资金费；
成交仍可定 mark（首笔合格 fill 写 `marks`）。可 delist 照旧（与 spot 正交）。

**全额抵押不可协商**：`spot_only` 没有报价通道，`last_index` 永不写，
mark 冻结在首笔合格成交价。杠杆仓位因此永远等不到引擎保证金意义上的
清算——亏损方按冻结 mark 仍是正权益，`withdraw` 的 `debit` 门也读同一
个 mark，于是把已被未实现亏损吃掉的保证金提走，赢家按真实价平仓时
金库收不抵付。所以 `spot_only` 必须 `im_bps == 10_000`：入场即锁定
= 名义额的最大亏损，mark 冻结不再影响偿付能力（`apply_fill_pair` 对
存量杠杆 `spot_only` 市场一律拒绝成交，不再产生新敞口）。

**价格区间**：每侧独立，`0` 表示该侧无界——`[min, 0]` 为只设下界、
`[0, max]` 为只设上界；只有两侧都设置时才要求 `min < max`；设置的边界须
落在 tick 网格上，否则 Risk。真实边界恰为 0 时写成最近的网格点（下界
`tick_size`、上界 `-tick_size`）。区间是**限价准入门**：越界限价单直接
`Risk`；market 单只会与已在带内准入的限价单成交，天然落在带内；ADL 的
场外成交价（按 mark）会被钳进区间；资金费率市场不允许声明区间（其簿价是
费率编码，另有 ±100% 费率带）。因此任何市场的成交都不会打到区间外。
`min_price`/`max_price` 建时定死，随 `params_91B` 进 book_leaf 承诺，
`ParamKey` 不可翻转。

**spot_only 的偿付不变量**（#47 C2）：`spot_only` 建市必须声明
`0 < min_price < max_price`。mark 冻结后不能用于保证金，所以每个 spot_only
仓位改为按区间最坏情况**预留**现金，且不读 mark：

```
多头 R = max(qty·entry（全额，im_bps=10 000）, qty·(entry − min) + fee(qty·max))
空头 R = max(qty·entry,                          qty·(max − entry) + fee(qty·max))
```

跨仓 `equity = collateral + 非 spot 仓位 uPnL − ΣR`（spot 仓位的 uPnL 视为 0、
不计 MM/IM、不会被清算）；逐仓 spot 仓位的桶必须 ≥ R。开仓门、挂单预留
（`resting_open_im`）都按该订单在区间内可能成交的最差价格计 R（另加本次
开仓 taker 费）；`withdraw` 的 `debit` 在原有 reduce-only 检查之外，还要求
提款后 `equity ≥ 0`，即不能动用预留。由此得到：任何持有 spot 仓位的账户，
以区间内**任意**价格平仓（含 taker 费）后现金都不为负，`apply_fill_pair`
的 claw 不会被触发，金库不会因冻结 mark 收不抵付。（例外：同一跨仓账户在
普通市场的清算缺口会先吃掉这部分现金，这与任何跨仓账户的既有风险相同。）
存量 spot 市场若不满足上述条件（杠杆、无区间或下界 ≤ 0），一律拒绝下单、
成交与清算（`spot_market_tradeable`），清算在动订单簿之前即返回 Risk。

`funding_rate` 同样建时定死、无 `ParamKey` 翻转：资金费率市场，簿价是
外部交易所资金费率的编码价（`encode_funding_price`，offset 域内恒正，
0 bps 可表示）。报价只写 `last_index`（不写 mark、不进 ±10% 钳位；
TWAP 环照记供 slash 使用）；fill 写 mark 需 ≥ 100 USD 名义额且费率步进
合法（首印与 index 差 ≤ `FUNDING_CAP_BPS`，此后每笔 ≤ max(|旧费率|/10,
1) bps，见 §6.2）；资金费按 peg 结算——首个观测只 arm
`last_funding_height`（不要求报告者或外部打印），此后每 14_400 高度窗口
总是重 arm，且仅在存在新鲜外部打印（`fresh_external_index`）时按
`funding_rate_cash` 付款（无打印则该窗口不付，时钟照走；diff 钳在该市场
`funding_cap_bps`，见 §6.2）。与 `spot_only` 互斥：
两者同时为 true → `Risk` 拒绝（烧费之前）。

下单时，FundingRate 的编码费率超过 ±10,000 bps 会被拒绝（平仓也适用）；
开仓所需保证金至少为 `max(bps(funding_notional, im_bps),
funding_notional × funding_cap_bps / 10_000)`，避免只覆盖常规 IM 而未覆盖 peg
上限风险。此外，按代码计算的市场 open interest 在 `funding_cap_bps` 下的最坏
赔付须不超过保险账户当前正 collateral，否则新开仓以 `Risk` 拒绝。此项只是
开仓准入上限，不是赔付承诺：离簿清算的残余缺口仍由本次 ADL 对手方正收益按比例
承担，保险不扣款。

delisted 市场（见 16.3 Delist 提案）拒绝新挂单；撤单与清算平仓仍允许
(清算路径不经 place 校验)。MVP 不做强制拍卖：存量仓位只能平仓或被清算。

### 16.3 提案投票

**CreateProposal**（tag 11）：创建者对指定市场提交参数修改提案，`key` 取
`ParamKey`（ImBps/MmBps/TakerFeeBps/KeeperRewardBps/Delist）；Delist 键的
value 必须为 0，否则 Risk 拒绝；bps 键按 finalize 同样的方式预演更新到
当前 `MarketParams`，结果不过 `risk_params_ok`（§16.2）即 Risk 拒绝。
并发上限：
`proposals.len() >= 64` 时新提案 Risk 拒绝（状态膨胀防护，exec
`create_proposal`）。创建门槛：
创建者 PERP 余额 ≥ `PROPOSAL_MIN_STAKE_PERP = 1_000`（仅门槛检查，
质押不锁定）。提案登记即固定两个快照：`created_seq` 与 quorum 分母
`supply_at_create = perp_supply`——期限与法定人数在创建时刻确定，任何副本
重放得出相同的通过判定。

**Vote**（tag 12）：权重取自**创建时刻的余额快照**
`Proposal.weight_snapshot`（`CreateProposal` 时对全部非零
`perp_balances` 冻结；余额为 0 的账户不入表，计票 `unwrap_or(0)`）。
此后充值/提款/烧毁都不改变该票权重——烧毁 PERP 既不能放大也不能规避
投票。每账户一票（`voted` 集合去重）；期限
`seq < deadline_seq = created_seq + PROPOSAL_DURATION_SEQS
= created_seq + 20_000 seqs`。

**FinalizeProposal**（tag 13）：任何人可触发，须 `seq ≥ deadline_seq` 且
未 finalized。通过条件：

```
yes > no  ∧  yes × PROPOSAL_QUORUM_DEN(100)
              ≥ supply_at_create × PROPOSAL_QUORUM_NUM(10)
```

即赞成票超过流通量快照的 **10%**。分母用创建时快照而非当前 supply：
烧毁/提款导致的后续流通量变化不会改写历史提案的通过判定（重放确定性的
另一面）。通过后先复检 `risk_params_ok`（§16.2）：合法才写回
`markets[m]` 对应字段；非法则**不写任何字段**（提案结果是 no-op，提案
仍被消耗）。Delist 键置 `delisted = true`——delisted 市场拒绝新挂单，
存量仓位只能平仓或被清算（§16.2）。

### 16.4 烧毁语义

烧毁统一走 `burn_perp`：入口为 CreateMarket 的上架费
`CREATE_MARKET_FEE_PERP = 10_000` 与 `SlashOracle`(tag 16) 罚没中的
烧毁份额（§7.2）。
烧毁 = 从 `perp_balances` 扣除并累计 `perp_burned` 统计量，**同时等额扣减
`perp_supply`**：supply 定义为可赎回流通量，通缩使后续提案的 quorum
分母随之收缩。

审计对账口径：侧链烧毁只动镜像账本，对应的真实 PERP **永久滞留在 vault
AA 中、不做链上销毁 sweep**——AA 对 PERP 处于超抵押状态。这是有意设计：
可赎回总量按 `perp_supply` 通缩，而链上 AA 余额不减少。对账时切勿把
"AA 持有 > Σ 可赎回"误判为资损缺口；差额恰等于 `perp_burned`。

### 16.5 债券解锁

预言机债券记入 `oracle_bonds`，与可自由支配的 `perp_balances` 分离：进入
债券的 PERP 不计投票权重、不可直接提款。退出走 `UnstakeOracle`(tag 15)：
进入 `ORACLE_UNBOND_HEIGHTS = 256` 高度的解锁排队（`oracle_unbonding`，
meta 叶承诺），到期后债券回到 `perp_balances`，再经双币种 Merkle 证明
出金（§10.5）。排队期间 `(market, oracle)` 已无债券——最新报价立即退出
中位数集合、后续报价被防御性忽略（§7.2）。
