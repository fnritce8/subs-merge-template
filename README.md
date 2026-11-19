# subs-merge-template

把多个订阅合并成一份带分流规则的 OpenClash / FlClash 配置，靠 GitHub Actions 每 6 小时自动更新，订阅链接从此不用手动换。

📖 **第一次部署请照着 [部署说明.md](部署说明.md) 做，5 个阶段、带故障排查表。**

- **多订阅合并**：任意多个订阅、任意起名字；每个订阅自动生成一个 `📦 名字` 分组，节点名统一带订阅名前缀
- **分流规则**：内置 Cash-All 规则模板（AI / 流媒体 / 社交等 24 个分类组、32 个规则集、地区自动分组、DNS 防泄露）
- **加单节点**：除了订阅，还能把单个节点链接（自建节点等）混进来一起用
- **加自定义规则**：想给某个域名指定走哪个组，填一条规则就行
- **换别人的规则模板**：内置模板不合口味时，填一个模板链接就能整套换掉分组和规则（支持本项目格式的 template.json，或任意一份完整的 Clash YAML 配置）
- **抗抽风**：某个订阅拉取失败或返回假数据时，自动用上一次的缓存顶上；校验不过不发布，客户端永远拿不到坏配置
- **公开私有随你**：仓库建公开版直接用 raw 链接；建私有的，把成品自动发到私密 Gist 分发（见下）

## 源格式要求

订阅地址返回的内容必须是 **vless / trojan 链接列表**（明文或 Base64 编码），edgetunnel 系的优选订阅就是这种。返回 Clash YAML 的订阅、以及 ss / hysteria2 等其他协议的节点，暂不解析。

## 部署（三步）

1. 点本页右上角 **Use this template → Create a new repository**，仓库名随便起，**Visibility 选 Public 或 Private 都行**（想藏起来就选 Private，后面按「私有仓库」一节多配两步）。
2. 进你新建的仓库 → **Settings → Secrets and variables → Actions → New repository secret**，添加名为 `SUBS` 的 Secret，内容一行一个订阅：

   ```
   名字1|https://example.com/sub?token=xxxx
   名字2|https://example.org/feed
   ```

3. 进 **Actions** 页，启用工作流，再手动 **Run workflow** 跑一次。之后每 6 小时自动更新（改频率：编辑 `.github/workflows/update.yml` 里的 cron）。

## 订阅链接

**公开仓库**，直接用仓库里成品的 raw 链接：

```
https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/out/openclash.yaml
```

FlClash 用同目录的 `flclash.yaml`。在 OpenClash「配置管理」里把链接加为订阅、打开自动更新即可。

**私有仓库**，raw 链接需要登录才能访问，客户端拉不到，改用私密 Gist 分发：

1. 打开 [gist.github.com](https://gist.github.com)，建一个 **Secret** gist，里面放两个同名文件 `openclash.yaml`、`flclash.yaml`（内容随便填，会被自动覆盖），记下 gist 地址里那串 ID。
2. 到 GitHub **Settings（账号设置）→ Developer settings → Personal access tokens → Tokens (classic)** 建一个 token，只勾 `gist` 一项权限。
3. 回仓库的 Secrets 再加两个：`GIST_TOKEN`（刚建的 token）、`GIST_ID`（第 1 步的 ID）。
4. 重跑一次工作流，订阅链接用：

   ```
   https://gist.githubusercontent.com/<你的用户名>/<GIST_ID>/raw/openclash.yaml
   ```

   Gist 链接等于密码，别外传。

## 可选 Secret

| 名字 | 作用 |
|---|---|
| `EXTRA_NODES` | 额外的单个节点链接，一行一个 `vless://` 或 `trojan://`。会并入一个名为「自定义」的分组，和订阅节点一起出现在全部/地区分组里。分组名可在仓库 **Variables** 里用 `EXTRA_LABEL` 修改。 |
| `EXTRA_RULES` | 额外的分流规则，一行一条 Clash 规则，例如 `DOMAIN-SUFFIX,example.com,✨ AI`、`IP-CIDR,1.2.3.0/24,DIRECT,no-resolve`。规则会插在兜底 `MATCH` 之前；目标必须是配置里已有的分组名、`DIRECT` 或 `REJECT`，写错会被跳过并在 Actions 日志里警告。 |
| `GIST_TOKEN` / `GIST_ID` | 见上「私有仓库」一节。两个都填了才会往 Gist 发。 |

仓库 **Variables** 还可调：

| 名字 | 作用 |
|---|---|
| `MIN_TOTAL_NODES` | 成品节点数低于这个数就不发布（默认 10） |
| `TEMPLATE_URL` | **换规则模板**：填一个模板文件的直链（raw 链接）。支持两种：① 本项目格式的 `template.json`；② 任意一份完整的 Clash YAML 配置——它的 DNS、规则集、规则和分组结构会被整套借用，组里的节点换成你自己的（分组间引用保留，地区组按地区填，`📦 订阅名`组按订阅填）。链接失效或格式不对时自动回退到内置模板，并在日志里 WARN。注意：subconverter 的 INI 模板（如 ACL4SSR 的 .ini 原文件）不能直接填，需要先转成上面两种格式之一。 |

## 其他说明

- 分流模板在 `template.json`（Cash-All 风格），想换规则体系可以替换它；地区识别在 `build.py` 的 `REGION_PATTERNS`。
- 订阅源地址只填在 Secret 里，不要写进代码、README 或提交记录。
- 每次成功拉取的原始内容会缓存在 `cache/` 并提交回仓库，这是「拉取失败用缓存顶上」的实现方式；公开仓库的话这份缓存也是公开的，介意就用私有仓库 + Gist。

## License

MIT
