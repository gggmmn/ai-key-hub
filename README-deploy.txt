AI 密钥网关（AI API Key Hub）
────────────────────────────────────────────────────────
纯 Python 标准库实现 —— 零第三方依赖、零 pip 包、零 CDN。

【目录结构】
  server.py             后端主程序
                         · 访问口令门（PBKDF2 加盐哈希 + 登录限流）
                         · OpenAI 兼容网关 /v1/models、/v1/chat/completions
                         · 多密钥按顺序自动故障转移（欠费/限速/失效自动跳过）
  static/index.html     管理界面（单文件，原生 JS + 内联 CSS）

【首次运行自动生成】
  data/data.json        密钥 / 设置 / 操作日志         权限 0600
  data/master.key       ★ 加密种子，丢了所有密钥永久无法解密   0600
  data/sessions.json    登录会话（默认记住 7 天）        0600
  logs/app.log          运行日志

【部署方式】
  一键（推荐）：把本包和 install.sh 放同一目录，然后
        bash install.sh
  脚本会自动检测并补装缺失依赖、问你要端口和口令、配好开机自启。

  手动：
        python3 server.py --port 47586 --data-dir ./data --no-tls

【客户端配置】
        Base URL :  http://<你的IP>:<端口>/v1
        API Key  :  后台「设置」里的网关令牌 gw-...
        模型名   :  后台「设置」里配置的那个名字（默认 auto）

【常用管理命令】
        重启      systemctl restart ai-keys
        看日志    journalctl -u ai-keys -f
        改口令    浏览器进后台 → 设置 → 修改访问口令

【关于「🧪 测试」按钮 —— 真发一条消息】
  卡片上的「🧪 测试」不是只看接口通不通，而是真的往该密钥发一条对话消息
  （max_tokens=1，只出 1 个 token，费用几乎为 0）：
    · 收到回复        → 判定「正常」，同时清掉冷却、恢复参与调度
    · 报错/超时/连不上 → 判定「不可用」，按错误类型进入冷却
                        （欠费 30 分钟 / 认证失败 60 分钟 / 限速 30 秒 / 5xx 60 秒）
    · 密钥没登记模型名 → 先自动拉一次 /models 取第一个来测；拉不到就提示你先填写模型名
  「🧪 批量测试全部密钥」同理，会逐个真发消息，并把没通过的密钥和原因列出来。
