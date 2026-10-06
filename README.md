# 燃气管线泄漏检测与隔离协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8333`。

- `app.py`：参数、依赖和服务生命周期。
- `src/domain.py`：管段、传感值、来源记录与回执校验。
- `src/rules.py`：泄漏评分、阀门顺序、修复、试压、恢复状态机。
- `src/repository.py`：SQLite、重复保护、乐观版本、动作摘要链、回执与对账。
- `src/service.py`：角色权限和业务编排。
- `src/http_api.py`：JSON 接口与首页。
- `src/audit.py`：内容摘要、链式摘要与可校验的审计事件哈希。

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8333
python3 app.py --db ./data.db --backfill     # 旧数据按时间顺序回填摘要后退出
python3 -m unittest discover -s tests -v
```

## 可核对的处置链

- **动作落摘要**：每个处置动作（核验/隔离/抢修/试压/复供/取消）落库时同时生成
  `content_digest`（动作内容指纹）和 `digest`（链式摘要 `sha256(上一动作摘要 + 内容指纹)`）。
  对应审计事件挂 `action_id` 与 `action_digest`，动作、审计互相锁死；审计哈希链仍按原算法逐条串联。
- **回执对账**：动作可带 `expected_receipts` 登记预期外部回执编号。外部回执按编号全局去重：
  - 首次送达：正文只记一次，挂内容摘要并写入审计链；
  - 同一份晚到：返回 `409 duplicate_receipt`，正文不覆盖，另在 `duplicate_deliveries` 留一条送达痕迹；
  - 没有任何动作登记过：入账为 `unexpected`，对账单独列出；
  - 编号属于另一处事件：返回 `409 receipt_wrong_item` 并拒收留痕（归属方记 `rejected_wrong_item`，
    被送错方记 `rejected_inbound`）。
- **对账结果**：`GET /api/items/<id>/reconciliation` 按编号逐条给出 `matched / missing / unexpected /
  duplicate_deliveries / rejected_*` 及汇总数。
- **链校验**：`GET /api/items/<id>/verify` 重算动作内容摘要、动作链、审计哈希链、动作↔审计↔回执挂钩，
  任一被篡改都会在 `errors` 里定位；旧数据未回填时列在 `pending_backfill`（不算篡改）。

## 并发与重试

- 两位值班员同时提交同一处事件（管线 + 管段 + 报警时间相同）：唯一约束只放一份进链，
  另一份收到 `409 duplicate_item`，响应 `details.existing_item_id` 指向已在链中的记录，按它重读/补登即可。
- 回执编号全局唯一：跨事件重复登记返回 `409 receipt_no_taken`，事务回滚不污染状态机。
- 关键状态动作仍要求 `expected_version` 乐观锁。

## 旧数据回填

旧库升级时只通过 `ALTER TABLE ADD COLUMN` 增加摘要/挂钩列，旧行原样可读，摘要先为空。
`--backfill` 按事件逐个、按时间顺序回填：

- 动作链整链重算（升级后、回填前的新动作曾从 GENESIS 起链，回填会重锚到旧动作之后）；
- 旧动作型审计事件按时间顺序与旧动作补挂钩；挂钩列不进审计哈希输入，**旧事件哈希一行不变**；
- 全程 WAL，按事件分批提交，回填期间旧记录仍可读；命令幂等，可重复执行。

## 接口

`GET /health`、`GET /api/state`、`POST /api/items`、`POST /api/items/<id>/sources`、
`POST /api/items/<id>/actions`（动作请求可带 `expected_receipts: ["RC-1", ...]`）、
`POST /api/items/<id>/receipts`、`GET /api/items/<id>/reconciliation`、
`GET /api/items/<id>/verify`，以及审计/动作/回执查询。身份与角色通过 `X-User-Id`、`X-Role` 头传递。
模型不替代 SCADA、管网水力计算或正式应急预案。
