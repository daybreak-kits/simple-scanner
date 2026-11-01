# REPORT_T1 — 全量 mock 真值验证

- 范围: plugins_corpus 833 个 read_only + supplement read_only 手工插件 + supplement 参数化插件(无参→WARN)

- mock: 127.0.0.1:43639 (RootURL 插件额外绑 127.0.0.1:80, 可用=True)
- 断言: 正样本 OUTCOME==vuln; 负样本 OUTCOME==safe; 参数化插件无参==warn

## 范围与口径

| 项 | 说明 |
|---|---|
| 语料总条目 | manifest.json 1500 条 (read_only 833 / risky 622 / excluded 45) |
| 本次验证范围 | manifest 中 risk_class=read_only 的全部 833 个 + supplement 手工插件 |
| supplement 纳入 | read_only 4 个 (CVE-2021-26084/2022-26134/2023-34362/2023-4966; 2026-10-26 用户裁决删除版本型 CVE-2026-109618/109619) |
| supplement 参数化 | 4 个 (CVE-2021-44228/2022-22965/2020-14882/2021-26855): 跳过正例注入, 只断言无参->WARN |
| supplement 排除 | CVE-2024-3400 (intrusive, 非 read_only) |
| 语料排除 | risky 622 / excluded 45 (含参考样例 CVE-2025-0133, risk_class=risky) |
| 外部目标 | 零: mock 仅绑 127.0.0.1, 不扫任何外部主机 |

## 方法

1. `tools/build_fixtures.py` 用 ast 静态解析每个插件的 REQS/MATCHERS 声明。
2. 正样本: 逐 matcher 反推命中所需内容 (word 原文 / regex 样本串 / 状态码 / 头字段); negative matcher 一律不投内容 (它要求"词缺席"); 用插件自身 `_match_one()` 复核。
3. 负样本: 请求级 matchers_condition=or -> 全部 matcher 必须为 False; =and -> 至少一个为 False; 默认空 body/空 header, 必要时注入 negative 词使其命中。
4. regex 样本串由 re._parser AST 反推生成 (LITERAL/IN/RANGE/BRANCH/REPEAT/SUBPATTERN 等), 每个样本都用 re.search 自检; 无法构造的 pattern 标 untestable, 不硬造。
5. `tools/verify_t1.py` 起 127.0.0.1 mock (随机高端口; RootURL 插件另绑 127.0.0.1:80), 按 (method, path) 精确路由, 每个插件跑 do_testing 两次断言 OUTCOME。
6. 路由键归一化: 折叠 "//"、去 "/./"、百分号编码大写 (与 requests/urllib3 客户端行为一致); mock 只发状态行 + fixture 自带头部 (不加 Server/Date, 否则 "^Set-Cookie" 类头部正则会被打断)。
7. 有效性自证: mock 侧统计 fixture 投递/路由未命中, 未命中即判 failed (负样本的 SAFE 不允许是假通过); 另跑反向对照实验 (正负样本对调, 断言必须翻转)。

## 五类计数

| 类别 | 数量 |
|---|---|
| 总数 | 841 |
| 通过 (正 vuln + 负 safe) | 837 |
| 失败 | 0 |
| untestable (fixture 无法构造) | 0 |
| 参数化 (无参→WARN 通过) | 4 |

通过率 = 100.00% (837/837)
fixture 构造阶段: 833/833 全部可构造, 耗时 1.2s
执行耗时: 3.3s

## 失败清单

无失败。

## untestable 原因分布

无。

## 有效性自证 (防空测/防假通过)

| 检查项 | 结果 |
|---|---|
| mock 侧 fixture 投递次数(正+负) | 1849 |
| mock 侧路由未命中(noroute) | 0 (命中失败即判 failed, 不计入通过) |
| 正样本落在插件自身 "matched ..." 分支 | 833 / 837 |
| 负样本落在插件自身 "no match" 分支 | 835 / 837 (其余为 supplement 插件自带文案) |
| 反向对照实验(正负样本对调, 断言必须翻转) | 19 / 19 翻转正确 |

### 反向对照明细

| 插件 | 负样本放正槽 | 正样本放负槽 | 判定 |
|---|---|---|---|
| 2016/CVE-2016-8527.py | safe | vuln | 翻转正确 |
| 2016/CVE-2016-7834.py | safe | vuln | 翻转正确 |
| 2017/CVE-2017-7615.py | safe | vuln | 翻转正确 |
| 2018/CVE-2018-13317.py | safe | vuln | 翻转正确 |
| 2018/CVE-2018-13380.py | safe | vuln | 翻转正确 |
| 2019/CVE-2019-15858.py | safe | vuln | 翻转正确 |
| 2020/CVE-2020-8115.py | safe | vuln | 翻转正确 |
| 2021/CVE-2021-31581.py | safe | vuln | 翻转正确 |
| 2021/CVE-2021-34187.py | safe | vuln | 翻转正确 |
| 2022/CVE-2022-32430.py | safe | vuln | 翻转正确 |
| 2023/CVE-2023-1496.py | safe | vuln | 翻转正确 |
| 2024/CVE-2024-49757.py | safe | vuln | 翻转正确 |
| 2024/CVE-2024-29029.py | safe | vuln | 翻转正确 |
| 2026/CVE-2026-29059.py | safe | vuln | 翻转正确 |
| 2026/CVE-2026-27796.py | safe | vuln | 翻转正确 |
| 2025/CVE-2025-54793.py | safe | vuln | 翻转正确 |
| 2021/CVE-2021-45232.py | safe | vuln | 翻转正确 |
| 2019/CVE-2019-11581.py | safe | vuln | 翻转正确 |
| 2022/CVE-2022-40443.py | safe | vuln | 翻转正确 |

## 逐插件判定表

| 插件 | 状态 | 断言 | 备注 |
|---|---|---|---|
| 2026/CVE-2026-0561.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?action=shield_action& / no match |
| 2026/CVE-2026-0702.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/vsfw/v1/videos / no match |
| 2026/CVE-2026-0717.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/lottiefiles/v1 / no match |
| 2026/CVE-2026-1277.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2026/CVE-2026-13153.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/essential-bloc / no match |
| 2026/CVE-2026-18072.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?_wplogin=35fe7057ffed / no match |
| 2026/CVE-2026-21445.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/monitor/message / no match |
| 2026/CVE-2026-23483.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/..%2F..%2F..%2 / no match |
| 2026/CVE-2026-24477.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/setup-complete sta / no match |
| 2026/CVE-2026-27176.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/command.php?qry=%22%3E / no match |
| 2026/CVE-2026-27796.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/trpc/integration.a / no match |
| 2026/CVE-2026-28141.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ngg_tag/cve-2026-28141 / no match |
| 2026/CVE-2026-29059.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/w/_/jobs_u/get_log / no match |
| 2026/CVE-2026-29183.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/icon/getDynamicIco / no match |
| 2026/CVE-2026-30928.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/4/config status=20 / no match |
| 2026/CVE-2026-30958.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/workflow/docs/..%2f..% / no match |
| 2026/CVE-2026-33868.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/web/%2Finteract.sh:443 / no match |
| 2026/CVE-2026-34605.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/icon/getDynamicIco / no match |
| 2026/CVE-2026-39339.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/persons/latest?byp / no match |
| 2026/CVE-2026-40105.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/bin/view/Sandbox/?view / no match |
| 2026/CVE-2026-40151.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/agents status=200 / no match |
| 2026/CVE-2026-4020.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/gravitysmtp/v1 / no match |
| 2026/CVE-2026-40878.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?session_expired=true& / no match |
| 2026/CVE-2026-41492.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/debug/vars status=200 / no match |
| 2026/CVE-2026-50229.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/examples/jsp/num/numgu / no match |
| 2026/CVE-2026-52774.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/NoSuchPage/widget?id=% / no match |
| 2026/CVE-2026-53519.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/dashboard%2e%2e/data/c / no match |
| 2026/CVE-2026-55549.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/auth/authorize?client_ / no match |
| 2026/CVE-2026-57582.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/srv/eng/catalog.search / no match |
| 2026/CVE-2026-6826.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ccm/system/dialogs/fil / no match |
| 2026/CVE-2026-8236.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php/ccm/system/d / no match |
| 2026/CVE-2026-9103.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/auto_login stat / no match |
| 2026/CVE-2026-9506.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cache/original/%2e%2e/ / no match |
| 2025/CVE-2025-10162.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/wooconvo/v1/do / no match |
| 2025/CVE-2025-10210.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/search?key=%27% / no match |
| 2025/CVE-2025-12480.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/management/admindataba / no match |
| 2025/CVE-2025-1595.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/getbaseconfig s / no match |
| 2025/CVE-2025-2127.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/extensions/realestate/ / no match |
| 2025/CVE-2025-2129.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/kernels status=200 / no match |
| 2025/CVE-2025-23061.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/posts?authorMatch={"$a / no match |
| 2025/CVE-2025-2709.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login.jsp?onlyOnePerVM / no match |
| 2025/CVE-2025-2711.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/help/systop.jsp?langco / no match |
| 2025/CVE-2025-2712.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/help/top.jsp?langcode= / no match |
| 2025/CVE-2025-27505.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rest.html status=200 / no match |
| 2025/CVE-2025-28228.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/controlloLogin.js stat / no match |
| 2025/CVE-2025-28367.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/BetterImageGallery / no match |
| 2025/CVE-2025-34038.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/js/hrm/getdata.jsp?cmd / no match |
| 2025/CVE-2025-41393.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?profile=</script><scr / no match |
| 2025/CVE-2025-4210.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/scim/v2/Users status=2 / no match |
| 2025/CVE-2025-4388.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/o/marketplace-app-mana / no match |
| 2025/CVE-2025-47813.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/loginok.html status=2 / no match |
| 2025/CVE-2025-53533.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/"onload=alert(document / no match |
| 2025/CVE-2025-54589.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?ru&filter=%3C%2Fscrip / no match |
| 2025/CVE-2025-54793.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639//interact.sh/en// stat / no match |
| 2025/CVE-2025-55749.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webapps/xwiki/WEB-INF/ / no match |
| 2025/CVE-2025-58179.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/_image?href=https://ra / no match |
| 2025/CVE-2025-58360.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/geoserver/wfs?service / no match |
| 2025/CVE-2025-59716.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/apps/guests/register/1 / no match |
| 2025/CVE-2025-61224.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/doku.php?id=start&do=s / no match |
| 2025/CVE-2025-6174.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/qwi / no match |
| 2025/CVE-2025-63387.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/console/api/system-fea / no match |
| 2025/CVE-2025-66472.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/bin/view/AppWithinMinu / no match |
| 2025/CVE-2025-68273.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/skServer/serialports s / no match |
| 2025/CVE-2025-8848.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ status=200 / no match |
| 2025/CVE-2025-9985.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/uploads/fif / no match |
| 2024/CVE-2024-0204.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/goanywhere/images/..;/ / no match |
| 2024/CVE-2024-0235.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/wp-admin/admin-ajax.p / no match |
| 2024/CVE-2024-10486.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/goo / no match |
| 2024/CVE-2024-11587.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/read.php?idName=1%3Csc / no match |
| 2024/CVE-2024-1208.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/wp/v2/sfwd-que / no match |
| 2024/CVE-2024-1209.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/wp/v2/sfwd-ass / no match |
| 2024/CVE-2024-1210.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/ldlms/v1/sfwd- / no match |
| 2024/CVE-2024-1212.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/access/set?param=enabl / no match |
| 2024/CVE-2024-13126.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/uploads/dow / no match |
| 2024/CVE-2024-1709.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/SetupWizard.aspx/{{ran / no match |
| 2024/CVE-2024-21644.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/render/info.html statu / no match |
| 2024/CVE-2024-22207.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/documentation/playwrig / no match |
| 2024/CVE-2024-22927.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/login.php?a=get_uploa / no match |
| 2024/CVE-2024-23055.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ status=200 / no match |
| 2024/CVE-2024-2340.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/uploads/fus / no match |
| 2024/CVE-2024-24116.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/system/config_menu.htm / no match |
| 2024/CVE-2024-24131.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/api.php/<script>al / no match |
| 2024/CVE-2024-25735.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/device/config status=2 / no match |
| 2024/CVE-2024-26331.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Admin/Admin.aspx statu / no match |
| 2024/CVE-2024-27497.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/position.js status=200 / no match |
| 2024/CVE-2024-29029.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/o/get/image?url=https: / no match |
| 2024/CVE-2024-30569.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/currentsetting.htm sta / no match |
| 2024/CVE-2024-30570.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/debuginfo.htm status=2 / no match |
| 2024/CVE-2024-3080.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/js/..%2f%2f/wizard.htm / no match |
| 2024/CVE-2024-3097.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/ngg/v1/admin/b / no match |
| 2024/CVE-2024-31621.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/API/V1/credentials sta / no match |
| 2024/CVE-2024-3273.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/nas_sharing.cg / no match |
| 2024/CVE-2024-32735.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/devices status= / no match |
| 2024/CVE-2024-32736.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/confup?mode=&ui / no match |
| 2024/CVE-2024-32737.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/confup?mode=lea / no match |
| 2024/CVE-2024-32738.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/ndconfig?mode=l / no match |
| 2024/CVE-2024-32739.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/ndconfig?mode=& / no match |
| 2024/CVE-2024-33113.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/getcfg.php?a=%0A_POST_ / no match |
| 2024/CVE-2024-33605.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/installed_emanual_list / no match |
| 2024/CVE-2024-33610.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/sessionlist.html statu / no match |
| 2024/CVE-2024-35627.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/data/v3/?key=%27-alert / no match |
| 2024/CVE-2024-35693.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?post_type=tsml_meetin / no match |
| 2024/CVE-2024-36837.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/products?limit=20& / no match |
| 2024/CVE-2024-37728.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Pic/Indexs?imgs=DJwkiE / no match |
| 2024/CVE-2024-3850.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/V1.0%3CsVg/onload=aler / no match |
| 2024/CVE-2024-40711.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/serverinfo stat / no match |
| 2024/CVE-2024-42852.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?portgw=80089948;%20al / no match |
| 2024/CVE-2024-4348.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/furniture/catalog/all- / no match |
| 2024/CVE-2024-45440.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/core/authorize.php sta / no match |
| 2024/CVE-2024-45591.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xwiki/rest/wikis/xwiki / no match |
| 2024/CVE-2024-4577.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/php-cgi/php-cgi.exe?% / no match |
| 2024/CVE-2024-46627.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rest/users/1/settings/ / no match |
| 2024/CVE-2024-49357.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/v1/users/image?path=/v / no match |
| 2024/CVE-2024-49757.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ui/login/register stat / no match |
| 2024/CVE-2024-50967.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rest/rights/ status=20 / no match |
| 2024/CVE-2024-51739.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webservices/rest.php?l / no match |
| 2024/CVE-2024-52762.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ganglia/?tz=%22%3E%3Cs / no match |
| 2024/CVE-2024-5421.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/info/dir?/ status=200 / no match |
| 2024/CVE-2024-54763.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login/hostinfo.cgi sta / no match |
| 2024/CVE-2024-54764.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login/hostinfo2.cgi st / no match |
| 2024/CVE-2024-5522.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/h5vp/v1/video/ / no match |
| 2024/CVE-2024-56159.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pages/index.astro.mjs. / no match |
| 2024/CVE-2024-5910.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/OS/startup/restore/res / no match |
| 2024/CVE-2024-6555.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/wp- / no match |
| 2024/CVE-2024-6646.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/downloadFile.php?file= / no match |
| 2024/CVE-2024-8963.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/client/index.php%3F.ph / no match |
| 2023/CVE-2023-1496.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/unsafe/plain/https://r / no match |
| 2023/CVE-2023-1719.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/bitrix/components/bitr / no match |
| 2023/CVE-2023-22232.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/system/download?downlo / no match |
| 2023/CVE-2023-22480.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/clusters/kubeco / no match |
| 2023/CVE-2023-23161.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/product.php?cid=1&&art / no match |
| 2023/CVE-2023-23492.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2023/CVE-2023-23752.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/index.php/v1/confi / no match |
| 2023/CVE-2023-24278.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/squid.svg?title=Not%20 / no match |
| 2023/CVE-2023-24322.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Dialog/FileDialog.aspx / no match |
| 2023/CVE-2023-24488.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/oauth/idp/logout?post_ / no match |
| 2023/CVE-2023-24733.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pmb/admin/convert/expo / no match |
| 2023/CVE-2023-26255.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/servlet/snjCus / no match |
| 2023/CVE-2023-27179.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/_admin/imgdownload.php / no match |
| 2023/CVE-2023-27639.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/tshirtecommerce/ajax. / no match |
| 2023/CVE-2023-27641.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wa.exe?REPORT&z=4&"><s / no match |
| 2023/CVE-2023-2796.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2023/CVE-2023-2813.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?s={{rand_base(6)}}%3C / no match |
| 2023/CVE-2023-29489.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cpanelwebcall/<img%20s / no match |
| 2023/CVE-2023-29506.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xwiki/authenticate/wik / no match |
| 2023/CVE-2023-30210.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/client/manage/ourphp_t / no match |
| 2023/CVE-2023-30212.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/client/manage/ourphp_o / no match |
| 2023/CVE-2023-30256.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?rand=1679996611398&co / no match |
| 2023/CVE-2023-32117.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/wp-json/igd/v1/get-us / no match |
| 2023/CVE-2023-3219.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2023/CVE-2023-32235.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/assets/built%2F..%2F.. / no match |
| 2023/CVE-2023-33568.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/public/ticket/ajax/aja / no match |
| 2023/CVE-2023-34020.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?rest_route=/ult/v2/re / no match |
| 2023/CVE-2023-34598.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?q=./gibbon.sql status / no match |
| 2023/CVE-2023-3479.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/templates/pages/debug_ / no match |
| 2023/CVE-2023-34843.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/static/..%5c..%5c..%5c / no match |
| 2023/CVE-2023-35155.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xwiki/bin/view/Main/?v / no match |
| 2023/CVE-2023-35156.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xwiki/bin/get/Flamingo / no match |
| 2023/CVE-2023-35159.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xwiki/bin/deletespace/ / no match |
| 2023/CVE-2023-35160.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xwiki/bin/view/XWiki/M / no match |
| 2023/CVE-2023-35161.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xwiki/bin/view/AppWith / no match |
| 2023/CVE-2023-35843.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/download/{{repeat('..% / no match |
| 2023/CVE-2023-35844.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/slack/image/sla / no match |
| 2023/CVE-2023-36144.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/exportCfgwithp / no match |
| 2023/CVE-2023-36346.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/print.php?nm_member=<s / no match |
| 2023/CVE-2023-36347.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/excel.php status=200 / no match |
| 2023/CVE-2023-37265.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/v1/folder?path=%2F sta / no match |
| 2023/CVE-2023-37266.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/v1/folder?path=%2F sta / no match |
| 2023/CVE-2023-37474.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/.cpr/%2Fetc%2Fpasswd s / no match |
| 2023/CVE-2023-37645.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/data/model/custom_mode / no match |
| 2023/CVE-2023-3765.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ajax-api/2.0/mlflow-ar / no match |
| 2023/CVE-2023-39598.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webmail/?mid={{to_lowe / no match |
| 2023/CVE-2023-39600.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webmail/?color="><img  / no match |
| 2023/CVE-2023-39676.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/modules/fieldpopupnews / no match |
| 2023/CVE-2023-39677.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/modules/simpleimportpr / no match |
| 2023/CVE-2023-40044.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/AHT/AHT_UI/public/js/a / no match |
| 2023/CVE-2023-40748.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/index.php?controller= / no match |
| 2023/CVE-2023-40749.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/index.php?controller= / no match |
| 2023/CVE-2023-40750.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/index.php?controller= / no match |
| 2023/CVE-2023-40751.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/index.php?controller= / no match |
| 2023/CVE-2023-40752.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/index.php?controller= / no match |
| 2023/CVE-2023-4169.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/api/sys/set_passwd st / no match |
| 2023/CVE-2023-4173.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/classified/%22%3E%3Cim / no match |
| 2023/CVE-2023-4174.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/search/index?q="><img+ / no match |
| 2023/CVE-2023-42343.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/opencms/cmisatom/cmis- / no match |
| 2023/CVE-2023-42442.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/terminal/sessio / no match |
| 2023/CVE-2023-43662.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/Image/withpath/C:\ / no match |
| 2023/CVE-2023-4415.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/api/sys/login status= / no match |
| 2023/CVE-2023-4451.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/install/index.php?1692 / no match |
| 2023/CVE-2023-44813.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/friends/ajax_invite?mo / no match |
| 2023/CVE-2023-44982.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/wp- / no match |
| 2023/CVE-2023-4547.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/search?filtered=1&q=te / no match |
| 2023/CVE-2023-45855.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/uploads/ status=200 / no match |
| 2023/CVE-2023-4714.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639 status=200 / no match |
| 2023/CVE-2023-49103.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/apps/graphapi/vendor/m / no match |
| 2023/CVE-2023-49293.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?%22%3E%3C/script%3E%3 / no match |
| 2023/CVE-2023-5003.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/ldap-authen / no match |
| 2023/CVE-2023-50290.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/solr/admin/metrics sta / no match |
| 2023/CVE-2023-50719.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/bin/view/Main/Search?r / no match |
| 2023/CVE-2023-50720.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/bin/view/Main/Search?s / no match |
| 2023/CVE-2023-50917.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/modules/thumb/thumb.ph / no match |
| 2023/CVE-2023-6065.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/qut / no match |
| 2023/CVE-2023-6275.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mobileredir/openApp.js / no match |
| 2023/CVE-2023-6380.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/system/modules/alkacon / no match |
| 2023/CVE-2023-6505.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/uploads/pri / no match |
| 2023/CVE-2023-6549.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/nf/auth/startwebview.d / no match |
| 2022/CVE-2022-0087.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/signin?from=https://in / no match |
| 2022/CVE-2022-0150.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?wahi=JzthbGVydChkb2N1 / no match |
| 2022/CVE-2022-0165.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-0169.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-0201.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?p=%3Cimg%20s / no match |
| 2022/CVE-2022-0208.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?mapp_iframe=1&mapid=- / no match |
| 2022/CVE-2022-0212.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-0218.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?rest_route=/ / no match |
| 2022/CVE-2022-0250.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin.php?pag / no match |
| 2022/CVE-2022-0271.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-0281.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/users/search_autho / no match |
| 2022/CVE-2022-0288.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639 status=200 / no match |
| 2022/CVE-2022-0342.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/export-cgi?cat / no match |
| 2022/CVE-2022-0378.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/module/?module=admin%2 / no match |
| 2022/CVE-2022-0432.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/embed.js status=200 / no match |
| 2022/CVE-2022-0540.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/InsightPluginShowGener / no match |
| 2022/CVE-2022-0594.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-0653.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/pro / no match |
| 2022/CVE-2022-0666.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/logout?redirect_to / no match |
| 2022/CVE-2022-0678.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/demo/api/logout?redire / no match |
| 2022/CVE-2022-0692.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php/interact.sh  / no match |
| 2022/CVE-2022-0735.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/users/sign_in status=2 / no match |
| 2022/CVE-2022-0869.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/user/login/?next=https / no match |
| 2022/CVE-2022-0885.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-1040.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/userportal/Controller / no match |
| 2022/CVE-2022-1054.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin.php?pag / no match |
| 2022/CVE-2022-1119.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/sim / no match |
| 2022/CVE-2022-1162.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/users/sign_in status=2 / no match |
| 2022/CVE-2022-1168.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/jobsearch/?sea / no match |
| 2022/CVE-2022-1170.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/resumes/?s=%22%3E%3Cim / no match |
| 2022/CVE-2022-1221.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/gwy / no match |
| 2022/CVE-2022-1392.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/vid / no match |
| 2022/CVE-2022-1439.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/module/?module=%27onm% / no match |
| 2022/CVE-2022-1598.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/wp/v2/asked-qu / no match |
| 2022/CVE-2022-1904.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-1910.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-1916.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-1933.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-1946.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-2130.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/editor_tools/module?ty / no match |
| 2022/CVE-2022-21500.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/OA_HTML/ibeCAcpSSOReg. / no match |
| 2022/CVE-2022-2185.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/users/sign_in status=2 / no match |
| 2022/CVE-2022-2187.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/options-gener / no match |
| 2022/CVE-2022-22242.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/error.php?SERVER_NAME= / no match |
| 2022/CVE-2022-2290.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/custom/%3Cimg%20src=x% / no match |
| 2022/CVE-2022-22954.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/catalog-portal/ui/oaut / no match |
| 2022/CVE-2022-23134.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/zabbix/setup.php statu / no match |
| 2022/CVE-2022-23178.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/aj.html?a=devi status= / no match |
| 2022/CVE-2022-23347.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php/Pan/ShareUrl / no match |
| 2022/CVE-2022-23348.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Runtime/Data/ms_admin. / no match |
| 2022/CVE-2022-2373.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/ssa/v1/users s / no match |
| 2022/CVE-2022-2376.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-23779.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/themes status=301 / no match |
| 2022/CVE-2022-23808.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/phpmyadmin/setup/index / no match |
| 2022/CVE-2022-23854.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/AccessAnywhere/%252e%2 / no match |
| 2022/CVE-2022-23944.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugin status=200 / no match |
| 2022/CVE-2022-24124.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/get-organizations? / no match |
| 2022/CVE-2022-24288.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/airflow/code?roo / no match |
| 2022/CVE-2022-24899.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/contao/%22%3e%3Cscript / no match |
| 2022/CVE-2022-24990.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/module/api.php?mobile/ / no match |
| 2022/CVE-2022-25125.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mdiy/dict/listExcludeA / no match |
| 2022/CVE-2022-25216.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/download/C%3a%2fwindow / no match |
| 2022/CVE-2022-25226.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cmd?cmd=connect status / no match |
| 2022/CVE-2022-25323.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin.back<img%20src=x / no match |
| 2022/CVE-2022-25356.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/SecurityGateway.dll?vi / no match |
| 2022/CVE-2022-25369.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Admin/Access/Setup/Def / no match |
| 2022/CVE-2022-2544.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp/wp-content/uploads/ / no match |
| 2022/CVE-2022-25481.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?s=example st / no match |
| 2022/CVE-2022-25488.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/ajax/avatar.php? / no match |
| 2022/CVE-2022-25489.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/widgets/debug.php?a=<s / no match |
| 2022/CVE-2022-2551.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/backups-dup / no match |
| 2022/CVE-2022-2552.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/backups-dup / no match |
| 2022/CVE-2022-25568.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/config/list status=200 / no match |
| 2022/CVE-2022-26148.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login?redirect=%2F sta / no match |
| 2022/CVE-2022-26159.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/web/service/se / no match |
| 2022/CVE-2022-26271.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index/download/index?n / no match |
| 2022/CVE-2022-26564.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/creaprezzi.php?prezzop / no match |
| 2022/CVE-2022-27593.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/photo/combine.php?type / no match |
| 2022/CVE-2022-27849.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/sim / no match |
| 2022/CVE-2022-27926.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/public/error.jsp?errCo / no match |
| 2022/CVE-2022-28363.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/goform/login_process?u / no match |
| 2022/CVE-2022-28365.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/goforms/rlminfo status / no match |
| 2022/CVE-2022-28508.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/browser_search_plugin. / no match |
| 2022/CVE-2022-28923.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%5C%5Cinteract.sh/%252 / no match |
| 2022/CVE-2022-28955.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/category_view.php stat / no match |
| 2022/CVE-2022-29349.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/onlinePreview?url=aHR0 / no match |
| 2022/CVE-2022-29548.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/carbon/admin/login.jsp / no match |
| 2022/CVE-2022-29775.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/logfile?d=crossdomain. / no match |
| 2022/CVE-2022-30512.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/dms/admin/accounts/pay / no match |
| 2022/CVE-2022-30776.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/atmail/index.php/admin / no match |
| 2022/CVE-2022-30777.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index_en.php?from=%22% / no match |
| 2022/CVE-2022-31268.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/resources//../WEB-INF/ / no match |
| 2022/CVE-2022-31269.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/test.txt status=200 / no match |
| 2022/CVE-2022-31299.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/payform.php?type=upgra / no match |
| 2022/CVE-2022-31373.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Solar_AiConf.php/%22%3 / no match |
| 2022/CVE-2022-31656.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/SAAS/t/_/;/WEB-INF/web / no match |
| 2022/CVE-2022-31798.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/card_scan.php?No=0000& / no match |
| 2022/CVE-2022-31846.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/live_mfg.shtml status= / no match |
| 2022/CVE-2022-31847.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/ExportAllSetti / no match |
| 2022/CVE-2022-31974.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/?page=reports&da / no match |
| 2022/CVE-2022-31975.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/?page=user/manag / no match |
| 2022/CVE-2022-31984.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/requests/take_ac / no match |
| 2022/CVE-2022-32015.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?q=category&s / no match |
| 2022/CVE-2022-32018.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?q=hiring&sea / no match |
| 2022/CVE-2022-32195.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/logout?next=%208%22onm / no match |
| 2022/CVE-2022-32429.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin-hax/ExportSett / no match |
| 2022/CVE-2022-32430.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cms/admin/group/all st / no match |
| 2022/CVE-2022-32444.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/loginsave.php?u=http:/ / no match |
| 2022/CVE-2022-32770.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?toast=%3C%2F / no match |
| 2022/CVE-2022-32771.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?success=%3C% / no match |
| 2022/CVE-2022-32772.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?msg=%3C%2Fsc / no match |
| 2022/CVE-2022-34328.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?lvl=author_s / no match |
| 2022/CVE-2022-34576.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/ExportAllSetti / no match |
| 2022/CVE-2022-35405.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/xmlrpc status=200 / no match |
| 2022/CVE-2022-35493.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/home/get_products?sear / no match |
| 2022/CVE-2022-36883.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/git/notifyCommit?url=1 / no match |
| 2022/CVE-2022-3766.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?search=1af%2 / no match |
| 2022/CVE-2022-38463.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/logout_redirect.do?sys / no match |
| 2022/CVE-2022-38553.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/search?query=%22%3E%3C / no match |
| 2022/CVE-2022-38627.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/badging/badge_template / no match |
| 2022/CVE-2022-3869.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?showmessage= / no match |
| 2022/CVE-2022-38812.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/author_posts.php?autho / no match |
| 2022/CVE-2022-38817.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/components/statestore  / no match |
| 2022/CVE-2022-39195.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/scripts/wa.exe?TICKET= / no match |
| 2022/CVE-2022-39952.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/configWizard/keyUploa / no match |
| 2022/CVE-2022-40443.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639//one/siteinfo.php stat / no match |
| 2022/CVE-2022-4057.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/uploads/ao_ / no match |
| 2022/CVE-2022-4063.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-40734.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/download?working_dir=% / no match |
| 2022/CVE-2022-40879.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/onlinePreview?url=aHR0 / no match |
| 2022/CVE-2022-41352.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/js/zimbraMail/share/mo / no match |
| 2022/CVE-2022-41473.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/search/?q=%3Cscript%3E / no match |
| 2022/CVE-2022-42118.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/web/guest/home?p_p_id= / no match |
| 2022/CVE-2022-42746.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ajax.php?f=getPipeline / no match |
| 2022/CVE-2022-42747.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ajax.php?f=getPipeline / no match |
| 2022/CVE-2022-42748.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ajax.php?f=getPipeline / no match |
| 2022/CVE-2022-42749.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ajax.php?f=getPipeline / no match |
| 2022/CVE-2022-4301.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-login.php?action=re / no match |
| 2022/CVE-2022-4320.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2022/CVE-2022-4321.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/pdf / no match |
| 2022/CVE-2022-45269.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/../../../../../../../. / no match |
| 2022/CVE-2022-45354.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/download-monit / no match |
| 2022/CVE-2022-45933.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/scrape/kube-system / no match |
| 2022/CVE-2022-46381.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/badging/badge_template / no match |
| 2022/CVE-2022-46888.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login.php?secret="><sc / no match |
| 2022/CVE-2022-46934.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/picturesPreview?curren / no match |
| 2022/CVE-2022-47945.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?lang=../../thinkphp/b / no match |
| 2022/CVE-2022-48165.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/ExportLogs.sh  / no match |
| 2021/CVE-2021-20031.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ status=200 / no match |
| 2021/CVE-2021-20114.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cache/backup/ status=2 / no match |
| 2021/CVE-2021-20137.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/luci/site_acce / no match |
| 2021/CVE-2021-20323.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/auth/realms/master/cl / no match |
| 2021/CVE-2021-21087.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cf_scripts/scripts/aja / no match |
| 2021/CVE-2021-21246.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rest/users/1 status=20 / no match |
| 2021/CVE-2021-21402.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Audio/1/hls/..%5C..%5C / no match |
| 2021/CVE-2021-21801.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/php/device_graph_page. / no match |
| 2021/CVE-2021-21802.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/php/device_graph_page. / no match |
| 2021/CVE-2021-21803.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/php/device_graph_page. / no match |
| 2021/CVE-2021-21816.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/messages status=200 / no match |
| 2021/CVE-2021-21972.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ui/vropspluginui/rest/ / no match |
| 2021/CVE-2021-22054.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Catalog/BlobHandler.as / no match |
| 2021/CVE-2021-22122.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/error3?msg=30&data=';a / no match |
| 2021/CVE-2021-22145.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/_bulk status=400 / no match |
| 2021/CVE-2021-22205.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/users/sign_in status=2 / no match |
| 2021/CVE-2021-22873.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ads/www/delivery/lg.ph / no match |
| 2021/CVE-2021-24146.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin.php?pag / no match |
| 2021/CVE-2021-24176.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/jh- / no match |
| 2021/CVE-2021-24210.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/pha / no match |
| 2021/CVE-2021-24226.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639 status=200 / no match |
| 2021/CVE-2021-24235.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/tour-list/?keywords=%3 / no match |
| 2021/CVE-2021-24237.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/properties/?keyword_se / no match |
| 2021/CVE-2021-24275.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin.php?pag / no match |
| 2021/CVE-2021-24276.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin.php?pag / no match |
| 2021/CVE-2021-24278.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/wp-admin/admin-ajax.p / no match |
| 2021/CVE-2021-24288.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?page=acymail / no match |
| 2021/CVE-2021-24291.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2021/CVE-2021-24316.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?post_type=post&s=%22% / no match |
| 2021/CVE-2021-24370.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/fan / no match |
| 2021/CVE-2021-24389.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/listings/?search_title / no match |
| 2021/CVE-2021-24406.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/community/?foro=signin / no match |
| 2021/CVE-2021-24435.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/titan-framework/lib/if / no match |
| 2021/CVE-2021-24495.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/mar / no match |
| 2021/CVE-2021-24666.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?rest_route=/ / no match |
| 2021/CVE-2021-24838.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/anycomment/v1/ / no match |
| 2021/CVE-2021-24910.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2021/CVE-2021-24987.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2021/CVE-2021-24997.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/guppy/v2/load- / no match |
| 2021/CVE-2021-25028.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin.php?pag / no match |
| 2021/CVE-2021-25033.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?noptin_ns=email_click / no match |
| 2021/CVE-2021-25085.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2021/CVE-2021-25111.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2021/CVE-2021-25118.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/wp/v2/posts?pe / no match |
| 2021/CVE-2021-25864.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/hue/assets/..%2F..%2F. / no match |
| 2021/CVE-2021-26085.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/s/1/_/;/WEB-INF/web.xm / no match |
| 2021/CVE-2021-26086.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/s/1/_/;/WEB-INF/web.xm / no match |
| 2021/CVE-2021-26247.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/auth_changepassword.ph / no match |
| 2021/CVE-2021-26475.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi/cal?year=2021%3C/t / no match |
| 2021/CVE-2021-26702.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi/dataset_dictionary / no match |
| 2021/CVE-2021-26710.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/r2w/signIn.do?urll=%22 / no match |
| 2021/CVE-2021-26723.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ics?tool=search&query= / no match |
| 2021/CVE-2021-27132.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/test.txt%0d%0aSet-Cook / no match |
| 2021/CVE-2021-27309.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mods/clansphere/lang_m / no match |
| 2021/CVE-2021-27310.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/clansphere/mods/clansp / no match |
| 2021/CVE-2021-27330.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/calendar/calendar_form / no match |
| 2021/CVE-2021-27519.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?SQ=0&srch=x" / no match |
| 2021/CVE-2021-27520.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?SQ=0&t=searc / no match |
| 2021/CVE-2021-27561.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/premise/front/getPingD / no match |
| 2021/CVE-2021-27670.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/core/proxy/json / no match |
| 2021/CVE-2021-27909.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/passwordreset?bundle=' / no match |
| 2021/CVE-2021-28169.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/static?/%2557EB-INF/we / no match |
| 2021/CVE-2021-28937.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/password.html status=2 / no match |
| 2021/CVE-2021-29442.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/nacos/v1/cs/ops/derby? / no match |
| 2021/CVE-2021-29484.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ghost/preview status=2 / no match |
| 2021/CVE-2021-29622.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/new/newhttp://interact / no match |
| 2021/CVE-2021-29625.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?server=db&username=ro / no match |
| 2021/CVE-2021-30049.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/KeepAlive.jsp?stamp=16 / no match |
| 2021/CVE-2021-30134.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/vendor/curl/curl/tests / no match |
| 2021/CVE-2021-3017.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.asp status=200 / no match |
| 2021/CVE-2021-3019.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/../conf/config.propert / no match |
| 2021/CVE-2021-30213.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/knowage/servlet/Adapte / no match |
| 2021/CVE-2021-30497.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/AvalancheWeb/image?ima / no match |
| 2021/CVE-2021-31195.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/owa/auth/frowny.aspx?a / no match |
| 2021/CVE-2021-31249.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/man.cgi?redirect=setti / no match |
| 2021/CVE-2021-31250.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/if.cgi?redirect=settin / no match |
| 2021/CVE-2021-31537.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rewe/prod/web/rewe_go_ / no match |
| 2021/CVE-2021-31581.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pme/database/pme/phinx / no match |
| 2021/CVE-2021-31589.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/appliance/login.ns?log / no match |
| 2021/CVE-2021-31602.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pentaho/api/userroleli / no match |
| 2021/CVE-2021-31682.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.jsp?operatorloca / no match |
| 2021/CVE-2021-31856.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/experimental/patte / no match |
| 2021/CVE-2021-3223.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ui_base/js/..%2f..%2f. / no match |
| 2021/CVE-2021-32478.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mod/lti/auth.php?redir / no match |
| 2021/CVE-2021-32618.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login?next=\\\interact / no match |
| 2021/CVE-2021-32682.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/elfinder/elfinde / no match |
| 2021/CVE-2021-32789.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?rest_route=/wc/store/ / no match |
| 2021/CVE-2021-32853.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/widgets/knowledgebase? / no match |
| 2021/CVE-2021-33221.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/service/v1/service-det / no match |
| 2021/CVE-2021-33558.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/js/log.js status=200 / no match |
| 2021/CVE-2021-33564.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/system/images/W1siZyIs / no match |
| 2021/CVE-2021-3374.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%2f/ status=200 / no match |
| 2021/CVE-2021-33807.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/gespage/doDownloadData / no match |
| 2021/CVE-2021-33904.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/security/hostSignon.do / no match |
| 2021/CVE-2021-34187.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/main/inc/ajax/model.aj / no match |
| 2021/CVE-2021-34370.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ssoAdapter/logoutActio / no match |
| 2021/CVE-2021-34473.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/autodiscover/autodisco / no match |
| 2021/CVE-2021-34630.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?page</script><script> / no match |
| 2021/CVE-2021-34805.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%5c%2e%2e%5c%2e%2e%5c% / no match |
| 2021/CVE-2021-35265.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/page/hello/1%22%3E%3Cs / no match |
| 2021/CVE-2021-35336.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/get_device_details / no match |
| 2021/CVE-2021-35380.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/file?valore=../../../. / no match |
| 2021/CVE-2021-35464.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/openam/oauth2/..;/ccve / no match |
| 2021/CVE-2021-35488.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/thruk/cgi-bin/login.cg / no match |
| 2021/CVE-2021-35587.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/oam/server/opensso/ses / no match |
| 2021/CVE-2021-3654.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639//interact.sh/%2f.. sta / no match |
| 2021/CVE-2021-36580.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webmail/basic/?referer / no match |
| 2021/CVE-2021-37304.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/jeecg-boot/actuator/ht / no match |
| 2021/CVE-2021-37305.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/jeecg-boot/sys/user/qu / no match |
| 2021/CVE-2021-37416.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/LoadFrame?frame_name=x / no match |
| 2021/CVE-2021-37538.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/module/smartblog/archi / no match |
| 2021/CVE-2021-37573.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/te%3Cimg%20src=x%20one / no match |
| 2021/CVE-2021-37704.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/vendor/phpfastcache/ph / no match |
| 2021/CVE-2021-37833.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/visualizza_tabelle.php / no match |
| 2021/CVE-2021-38146.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/home/download status= / no match |
| 2021/CVE-2021-3831.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mobile/shop/lg/mispwap / no match |
| 2021/CVE-2021-38702.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/tweb/ft.php?u=%3C%2Fsc / no match |
| 2021/CVE-2021-38704.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cliniccases/lib/php/da / no match |
| 2021/CVE-2021-38751.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639 status=200 / no match |
| 2021/CVE-2021-39211.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ajax/telemetry.php sta / no match |
| 2021/CVE-2021-39226.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/snapshots/:key sta / no match |
| 2021/CVE-2021-39327.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/bps-backup/ / no match |
| 2021/CVE-2021-39501.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?m=user&c=Use / no match |
| 2021/CVE-2021-40149.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/self.key status=200 / no match |
| 2021/CVE-2021-40150.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/conf/nginx.conf status / no match |
| 2021/CVE-2021-40542.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Ajax_url_encode.php?li / no match |
| 2021/CVE-2021-40661.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/IND780/excalweb.dll?we / no match |
| 2021/CVE-2021-40859.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/about_state status=200 / no match |
| 2021/CVE-2021-40868.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login.html?returnTo=%3 / no match |
| 2021/CVE-2021-40875.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/files.md5 status=200 / no match |
| 2021/CVE-2021-41174.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/dashboard/snapshot/%7B / no match |
| 2021/CVE-2021-41192.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/reset/IjEi.YhAmmQ.cdQp / no match |
| 2021/CVE-2021-41381.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/.//WEB-INF/classes/MET / no match |
| 2021/CVE-2021-41648.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/action.php status=200 / no match |
| 2021/CVE-2021-41649.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/homeaction.php status / no match |
| 2021/CVE-2021-41826.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/auth/logout?continue=/ / no match |
| 2021/CVE-2021-41878.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/lostpassword.php/n4gap / no match |
| 2021/CVE-2021-41951.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/wordpress_sso/ / no match |
| 2021/CVE-2021-42063.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/SAPIrExtHelp/random/SA / no match |
| 2021/CVE-2021-42551.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/NetBiblio/search/short / no match |
| 2021/CVE-2021-42565.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ie50/system/login/SysL / no match |
| 2021/CVE-2021-42566.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ie50/system/login/SysL / no match |
| 2021/CVE-2021-42627.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wan.htm status=200 / no match |
| 2021/CVE-2021-43062.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/fmlurlsvc/?=&url=https / no match |
| 2021/CVE-2021-43574.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?format=%22%3E%3Cscrip / no match |
| 2021/CVE-2021-43725.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?data[performredirect] / no match |
| 2021/CVE-2021-43810.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/adm_program/system/red / no match |
| 2021/CVE-2021-44077.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/RestAPI/ImportTechnici / no match |
| 2021/CVE-2021-44138.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/;/WEB-INF/web.xml stat / no match |
| 2021/CVE-2021-44152.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/goforms/menu status=20 / no match |
| 2021/CVE-2021-44427.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/Side.php status=200 / no match |
| 2021/CVE-2021-45027.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/oliver/FileServlet?sou / no match |
| 2021/CVE-2021-45092.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/lab.html?vpath=//inter / no match |
| 2021/CVE-2021-45232.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/apisix/admin/migrate/e / no match |
| 2021/CVE-2021-45380.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/templates/m/inc_head.p / no match |
| 2021/CVE-2021-45422.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/goform/activate_proces / no match |
| 2021/CVE-2021-46104.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%252e%252e%252f%252e%2 / no match |
| 2021/CVE-2021-46371.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/v1/users status=20 / no match |
| 2021/CVE-2021-46379.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/boafrm/formWlanRedirec / no match |
| 2021/CVE-2021-46387.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Forms/rpAuth_1?id=</fo / no match |
| 2020/CVE-2020-0618.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ReportServer/Pages/Rep / no match |
| 2020/CVE-2020-10148.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/web.config.i18n.ashx?l / no match |
| 2020/CVE-2020-10220.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/commands.inc.php?searc / no match |
| 2020/CVE-2020-10532.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rest/domains/list?sort / no match |
| 2020/CVE-2020-10546.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/compliancepolicies.inc / no match |
| 2020/CVE-2020-10547.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/compliancepolicyelemen / no match |
| 2020/CVE-2020-10548.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/devices.inc.php?search / no match |
| 2020/CVE-2020-10549.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/snippets.inc.php?searc / no match |
| 2020/CVE-2020-11034.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?redirect=/\/ / no match |
| 2020/CVE-2020-11450.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/MicroStrategyWS/happya / no match |
| 2020/CVE-2020-11529.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%252f%255cinteract.sh% / no match |
| 2020/CVE-2020-11710.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639 status=200 / no match |
| 2020/CVE-2020-11738.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin-ajax.ph / no match |
| 2020/CVE-2020-11853.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ucmdb-api/connect stat / no match |
| 2020/CVE-2020-11854.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ucmdb-api/connect stat / no match |
| 2020/CVE-2020-11930.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/does_not_exist"%22%3E% / no match |
| 2020/CVE-2020-12054.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?s=%3Cimg%20src%3Dx%20 / no match |
| 2020/CVE-2020-12124.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/live_api.cgi?p / no match |
| 2020/CVE-2020-12127.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/ExportAllSetti / no match |
| 2020/CVE-2020-12447.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%2e%2e%2f%2e%2e%2f%2e% / no match |
| 2020/CVE-2020-12478.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/files/ldap.debug.txt s / no match |
| 2020/CVE-2020-12641.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/installer/index.php s / no match |
| 2020/CVE-2020-13158.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/fw.progrss.details.php / no match |
| 2020/CVE-2020-13379.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/avatar/1%3fd%3dhttp%3A / no match |
| 2020/CVE-2020-13700.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/acf/v3/options / no match |
| 2020/CVE-2020-13820.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/OneView/view/center?a% / no match |
| 2020/CVE-2020-13927.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/experimental/lates / no match |
| 2020/CVE-2020-13937.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/kylin/api/admin/config / no match |
| 2020/CVE-2020-14092.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?cffaction=get_data_fr / no match |
| 2020/CVE-2020-14179.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/secure/QueryComponent! / no match |
| 2020/CVE-2020-14181.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/secure/ViewUserHover.j / no match |
| 2020/CVE-2020-14408.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/auth/login?to=/92874%2 / no match |
| 2020/CVE-2020-14413.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Devices-Config.php?sta / no match |
| 2020/CVE-2020-15050.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/../../../../../../../. / no match |
| 2020/CVE-2020-15129.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639 status=302 / no match |
| 2020/CVE-2020-15148.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?r=test/sss&d / no match |
| 2020/CVE-2020-15227.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/nette.micro/?callback= / no match |
| 2020/CVE-2020-15500.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?key=%27%3E%22%3Csvg%2 / no match |
| 2020/CVE-2020-15718.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Modules.php?modname=Us / no match |
| 2020/CVE-2020-15895.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/info.php?RESULT=",msgA / no match |
| 2020/CVE-2020-15920.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/PDC/ajaxreq.php?PARAM / no match |
| 2020/CVE-2020-16952.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639 status=200 / no match |
| 2020/CVE-2020-17362.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?s=%3C%2Fscript%3E%3Cs / no match |
| 2020/CVE-2020-17453.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/carbon/admin/login.jsp / no match |
| 2020/CVE-2020-17506.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/fw.login.php?apikey=%2 / no match |
| 2020/CVE-2020-17519.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/jobmanager/logs/..%252 / no match |
| 2020/CVE-2020-19282.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/error?msg=%3C%2Fscript / no match |
| 2020/CVE-2020-19283.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/newVersion?callback=%3 / no match |
| 2020/CVE-2020-19295.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/weibo/topic/%3C%2Fscri / no match |
| 2020/CVE-2020-19360.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/fhem/FileLog_logWrappe / no match |
| 2020/CVE-2020-1943.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/control/stream?content / no match |
| 2020/CVE-2020-19515.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/install/index.php?step / no match |
| 2020/CVE-2020-19625.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/tests/support/stores/t / no match |
| 2020/CVE-2020-20300.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/public/index.php/home / no match |
| 2020/CVE-2020-20601.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?g=g&m=Door&a / no match |
| 2020/CVE-2020-2096.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/gitlab/build_now%3C%2F / no match |
| 2020/CVE-2020-20982.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/passport/index.php?act / no match |
| 2020/CVE-2020-2140.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/descriptorByName/Audit / no match |
| 2020/CVE-2020-21998.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/homeautomation_v3_3_2/ / no match |
| 2020/CVE-2020-22208.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plus/ajax_street.php?a / no match |
| 2020/CVE-2020-22209.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plus/ajax_common.php?a / no match |
| 2020/CVE-2020-22210.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plus/ajax_officebuildi / no match |
| 2020/CVE-2020-22211.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plus/ajax_street.php?a / no match |
| 2020/CVE-2020-22840.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/email_passthrough.php? / no match |
| 2020/CVE-2020-23015.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?url=http://interact.s / no match |
| 2020/CVE-2020-23517.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login/?uid=%22%3E%3Csc / no match |
| 2020/CVE-2020-24223.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/contact.php?theme=tes% / no match |
| 2020/CVE-2020-24312.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/uploads/wp- / no match |
| 2020/CVE-2020-24550.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/find_v2/_click?_t_id=& / no match |
| 2020/CVE-2020-24571.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/../../../../../../../. / no match |
| 2020/CVE-2020-24701.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ajax/apps/manifests?ac / no match |
| 2020/CVE-2020-24902.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?action=post& / no match |
| 2020/CVE-2020-24903.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/CuteSoft_Client/CuteEd / no match |
| 2020/CVE-2020-24912.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/assets/_core/php/prof / no match |
| 2020/CVE-2020-25078.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/config/getuser?index=0 / no match |
| 2020/CVE-2020-25495.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/manlist?sectio / no match |
| 2020/CVE-2020-2551.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/console/login/LoginFor / no match |
| 2020/CVE-2020-25540.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin.html?s=admin/api / no match |
| 2020/CVE-2020-25780.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/SearchSvc/CVSearchSer / no match |
| 2020/CVE-2020-26073.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/dataservice/disasterre / no match |
| 2020/CVE-2020-26836.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/sap/public/bc/icf/logo / no match |
| 2020/CVE-2020-26876.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-json/wp/v2/lesson/1 / no match |
| 2020/CVE-2020-2733.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/manage/fileDownloader? / no match |
| 2020/CVE-2020-27361.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pme/media/ status=200 / no match |
| 2020/CVE-2020-27735.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/help/english/index.htm / no match |
| 2020/CVE-2020-27838.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/auth/realms/master/cli / no match |
| 2020/CVE-2020-27982.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webmail/?language=%22% / no match |
| 2020/CVE-2020-27986.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/settings/values st / no match |
| 2020/CVE-2020-29164.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pacs/login.php?message / no match |
| 2020/CVE-2020-29453.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/s/1/_/%2e/WEB-INF/clas / no match |
| 2020/CVE-2020-3187.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/+CSCOE+/session_passwo / no match |
| 2020/CVE-2020-3452.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/+CSCOT+/translation-ta / no match |
| 2020/CVE-2020-35234.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/eas / no match |
| 2020/CVE-2020-35338.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/server/ status=200 / no match |
| 2020/CVE-2020-35598.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/advanced_component_sys / no match |
| 2020/CVE-2020-35729.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/actions/authenticate. / no match |
| 2020/CVE-2020-35736.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/downloads/..%2f..%2f.. / no match |
| 2020/CVE-2020-35774.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/histograms?h=%3C / no match |
| 2020/CVE-2020-35846.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/auth/check status=200 / no match |
| 2020/CVE-2020-35848.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/auth/newpassword stat / no match |
| 2020/CVE-2020-36289.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/secure/QueryComponentR / no match |
| 2020/CVE-2020-36365.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/backend/admin/common/c / no match |
| 2020/CVE-2020-36723.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/index.php?dow / no match |
| 2020/CVE-2020-4427.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/albatross/saml/idpSele / no match |
| 2020/CVE-2020-4463.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/os/mxperson status=20 / no match |
| 2020/CVE-2020-5284.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/_next/static/../server / no match |
| 2020/CVE-2020-5405.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/a/b/%252f..%252f..%252 / no match |
| 2020/CVE-2020-5410.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/..%252F..%252F..%252F. / no match |
| 2020/CVE-2020-5847.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webGui/images/green-on / no match |
| 2020/CVE-2020-6171.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639?lang=%22%3E%3C%2Fscrip / no match |
| 2020/CVE-2020-6637.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/account/index.php sta / no match |
| 2020/CVE-2020-7943.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/metrics/v1/mbeans stat / no match |
| 2020/CVE-2020-8115.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/www/delivery/afr.php?r / no match |
| 2020/CVE-2020-8497.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pandora_console/attach / no match |
| 2020/CVE-2020-8512.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webmail/?color=%22%3E% / no match |
| 2020/CVE-2020-8982.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/XmlPeek.aspx?dt=\\..\\ / no match |
| 2020/CVE-2020-9036.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?v=d&p=%22;al / no match |
| 2020/CVE-2020-9047.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/version.web status=200 / no match |
| 2020/CVE-2020-9315.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admingui/version/serve / no match |
| 2020/CVE-2020-9344.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/servlet/svnweb / no match |
| 2020/CVE-2020-9376.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/getcfg.php status=200 / no match |
| 2020/CVE-2020-9425.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/settings.php status=20 / no match |
| 2020/CVE-2020-9483.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/graphql status=200 / no match |
| 2020/CVE-2020-9484.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.jsp status=500 / no match |
| 2020/CVE-2020-9757.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/actions/seomatic/meta- / no match |
| 2019/CVE-2019-0221.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/printenv.shtml?{{url_e / no match |
| 2019/CVE-2019-0230.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?id={{rand_base(6)}}%2 / no match |
| 2019/CVE-2019-10068.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/CMSPages/Staging/Sync / no match |
| 2019/CVE-2019-10092.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%5cgoogle.com/evil.htm / no match |
| 2019/CVE-2019-10098.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/http%3A%2F%2Fwww.inter / no match |
| 2019/CVE-2019-1010290.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/modules/babel/redirect / no match |
| 2019/CVE-2019-10232.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/glpi/scripts/unlock_ta / no match |
| 2019/CVE-2019-10475.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugin/build-metrics/g / no match |
| 2019/CVE-2019-10692.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?rest_route=/wpgmza/v1 / no match |
| 2019/CVE-2019-10717.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/filemanager?path=% / no match |
| 2019/CVE-2019-11248.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/debug/pprof/ status=20 / no match |
| 2019/CVE-2019-11581.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/secure/ContactAdminist / no match |
| 2019/CVE-2019-12461.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/log?type=%22%3C/script / no match |
| 2019/CVE-2019-12581.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/free_time_failed.cgi?e / no match |
| 2019/CVE-2019-12583.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/free_time.cgi status=2 / no match |
| 2019/CVE-2019-12593.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webmail/calendar/minim / no match |
| 2019/CVE-2019-12962.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mobile/index.php statu / no match |
| 2019/CVE-2019-13462.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/WidgetHandler.ashx?Met / no match |
| 2019/CVE-2019-14205.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/ada / no match |
| 2019/CVE-2019-14223.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/share/page/dologin st / no match |
| 2019/CVE-2019-14312.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/tools/sourceViewer/ind / no match |
| 2019/CVE-2019-14322.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/base_import/static/c:/ / no match |
| 2019/CVE-2019-14696.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?r=students/g / no match |
| 2019/CVE-2019-14974.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mobile/error-not-suppo / no match |
| 2019/CVE-2019-15043.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/api/snapshots status= / no match |
| 2019/CVE-2019-15501.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/scripts/wa.exe?OK=%3C% / no match |
| 2019/CVE-2019-15858.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/ins / no match |
| 2019/CVE-2019-15859.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/password.jsn status=20 / no match |
| 2019/CVE-2019-16097.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/api/users status=201 / no match |
| 2019/CVE-2019-16313.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/action/usermanager.htm / no match |
| 2019/CVE-2019-16469.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/mnt/overlay/dam/gui/co / no match |
| 2019/CVE-2019-1653.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/config.exp sta / no match |
| 2019/CVE-2019-16662.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/install/lib/ajaxHandle / no match |
| 2019/CVE-2019-16996.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/?n=product&c=pro / no match |
| 2019/CVE-2019-17418.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/?n=language&c=la / no match |
| 2019/CVE-2019-17503.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/osm/REGISTER.cmd statu / no match |
| 2019/CVE-2019-17506.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/getcfg.php status=200 / no match |
| 2019/CVE-2019-17564.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/com.example.TestServi / no match |
| 2019/CVE-2019-17671.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?static=1&order=asc st / no match |
| 2019/CVE-2019-18393.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/search/..\..\. / no match |
| 2019/CVE-2019-18957.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/MicroStrategyLibrary/a / no match |
| 2019/CVE-2019-19134.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/hma / no match |
| 2019/CVE-2019-19781.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/vpn/../vpns/cfg/smb.co / no match |
| 2019/CVE-2019-19908.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plus/pass_reset.php?L= / no match |
| 2019/CVE-2019-19985.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-admin/admin.php?pag / no match |
| 2019/CVE-2019-20085.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/..%2F..%2F..%2F..%2F.. / no match |
| 2019/CVE-2019-20141.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/data/autosuggest-remot / no match |
| 2019/CVE-2019-20210.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?search_term=%3C%2Fscr / no match |
| 2019/CVE-2019-20933.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/query?db=db&q=SHOW%20D / no match |
| 2019/CVE-2019-2588.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/xmlpserver/servlet/adf / no match |
| 2019/CVE-2019-3401.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/secure/ManageFilters.j / no match |
| 2019/CVE-2019-3402.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/secure/ConfigurePortal / no match |
| 2019/CVE-2019-3911.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/__r2/query-printRows.v / no match |
| 2019/CVE-2019-3912.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/labkey/__r1/login-logi / no match |
| 2019/CVE-2019-6112.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/sell-media-search/?key / no match |
| 2019/CVE-2019-6340.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/node/1?_format=hal_js / no match |
| 2019/CVE-2019-6802.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/%0d%0aSet-Cookie:crlfi / no match |
| 2019/CVE-2019-7219.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webapp/?fccc%27\%22%3E / no match |
| 2019/CVE-2019-7255.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/badging/badge_template / no match |
| 2019/CVE-2019-7275.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/updating.jsp?url=https / no match |
| 2019/CVE-2019-7543.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/kindeditor/php/demo.p / no match |
| 2019/CVE-2019-7609.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/api/timelion/run stat / no match |
| 2019/CVE-2019-8442.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/s/1/_/WEB-INF/classes/ / no match |
| 2019/CVE-2019-8449.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rest/api/latest/groupu / no match |
| 2019/CVE-2019-8903.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/.%2e/.%2e/.%2e/.%2e/.% / no match |
| 2019/CVE-2019-8937.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/hoteldruid/visualizza_ / no match |
| 2019/CVE-2019-9632.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/CDGServer3/ClientAjax / no match |
| 2019/CVE-2019-9955.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?mp_idx=%22;alert(%271 / no match |
| 2018/CVE-2018-0127.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/dumpmdm.cmd status=200 / no match |
| 2018/CVE-2018-0296.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/+CSCOU+/../+CSCOE+/fil / no match |
| 2018/CVE-2018-1000129.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/api/jolokia/read<svg%2 / no match |
| 2018/CVE-2018-1000671.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/sympa?referer=http://i / no match |
| 2018/CVE-2018-1000861.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/securityRealm/user/adm / no match |
| 2018/CVE-2018-10095.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/dolibarr/adherents/car / no match |
| 2018/CVE-2018-10141.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/global-protect/login.e / no match |
| 2018/CVE-2018-10201.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/.../.../.../.../.../.. / no match |
| 2018/CVE-2018-10230.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?debug_host=% / no match |
| 2018/CVE-2018-10735.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/nagiosql/admin/command / no match |
| 2018/CVE-2018-10736.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/nagiosql/admin/info.ph / no match |
| 2018/CVE-2018-10738.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/nagiosql/admin/menuac / no match |
| 2018/CVE-2018-10823.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/chkisg.htm%3FSip%3D1.1 / no match |
| 2018/CVE-2018-11409.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/en-US/splunkd/__raw/se / no match |
| 2018/CVE-2018-11709.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php/community/?% / no match |
| 2018/CVE-2018-11759.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/jkstatus status=200 / no match |
| 2018/CVE-2018-11784.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639//interact.sh status=20 / no match |
| 2018/CVE-2018-12054.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/img.php?f=/./etc/./pas / no match |
| 2018/CVE-2018-1207.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/login?LD_DEBUG / no match |
| 2018/CVE-2018-12095.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cms/info.php?mod=list% / no match |
| 2018/CVE-2018-12300.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/echo-server.html?code= / no match |
| 2018/CVE-2018-12634.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/html/log status=200 / no match |
| 2018/CVE-2018-12675.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/web/cgi-bin/hi3510/par / no match |
| 2018/CVE-2018-1271.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/static/%255c%255c..%25 / no match |
| 2018/CVE-2018-12998.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/servlet/com.adventnet. / no match |
| 2018/CVE-2018-13317.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/password.htm status=20 / no match |
| 2018/CVE-2018-13379.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/remote/fgt_lang?lang=/ / no match |
| 2018/CVE-2018-13380.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/message?title=x&msg=%2 / no match |
| 2018/CVE-2018-14013.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/zimbra/h/search?si=1&s / no match |
| 2018/CVE-2018-14474.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login?next=http://inte / no match |
| 2018/CVE-2018-14574.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639//www.interact.sh statu / no match |
| 2018/CVE-2018-14931.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/IntellectMain.jsp?Inte / no match |
| 2018/CVE-2018-14933.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/upgrade_handle.php?cmd / no match |
| 2018/CVE-2018-15745.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/WEBACCOUNT.CGI?OkBtn=+ / no match |
| 2018/CVE-2018-16139.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/bibliopac/bin/wxis.exe / no match |
| 2018/CVE-2018-16668.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/html/repository status / no match |
| 2018/CVE-2018-16670.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/services/user/values.x / no match |
| 2018/CVE-2018-16671.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/html/device-id status= / no match |
| 2018/CVE-2018-16761.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/select_project.php?url / no match |
| 2018/CVE-2018-16979.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/captcha/crypt/ / no match |
| 2018/CVE-2018-18570.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wicket/resource/nl.pla / no match |
| 2018/CVE-2018-18608.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plus/feedback.php/rp4h / no match |
| 2018/CVE-2018-18775.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/microstrategy7/Login.a / no match |
| 2018/CVE-2018-18777.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/WebMstr7/servlet/mstrW / no match |
| 2018/CVE-2018-18809.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/jasperserver-pro/repor / no match |
| 2018/CVE-2018-19386.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/iwc/idcStateError.iwc? / no match |
| 2018/CVE-2018-19439.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/sgdadmin/faces/com_sun / no match |
| 2018/CVE-2018-19877.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/src/login.php?referer= / no match |
| 2018/CVE-2018-20062.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639?s=index/think\app/invo / no match |
| 2018/CVE-2018-20463.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/jsm / no match |
| 2018/CVE-2018-20470.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/_s_/dyn/Log_highlight? / no match |
| 2018/CVE-2018-20608.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/imcat/root/tools/adbug / no match |
| 2018/CVE-2018-20824.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/plugins/servlet/Wallbo / no match |
| 2018/CVE-2018-20985.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/wp-content/plugins/wp / no match |
| 2018/CVE-2018-2791.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cs/Satellite?pagename= / no match |
| 2018/CVE-2018-3167.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/OA_HTML/lcmServiceCon / no match |
| 2018/CVE-2018-5230.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/pages/includes/status- / no match |
| 2018/CVE-2018-5233.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/tools/a--%3C%2Fs / no match |
| 2018/CVE-2018-5316.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/sag / no match |
| 2018/CVE-2018-5715.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?action=Login / no match |
| 2018/CVE-2018-6200.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/redirector.php?url=htt / no match |
| 2018/CVE-2018-6605.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/index.php?option=com_ / no match |
| 2018/CVE-2018-6910.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/include/downmix.inc.ph / no match |
| 2018/CVE-2018-7251.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/anchor/errors.log stat / no match |
| 2018/CVE-2018-7314.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?option=com_p / no match |
| 2018/CVE-2018-7490.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/..%2f..%2f..%2f..%2f.. / no match |
| 2018/CVE-2018-7653.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?m=search&c=i / no match |
| 2018/CVE-2018-7662.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/includes/mysql2i/mysql / no match |
| 2018/CVE-2018-7700.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/tag_test_action.php?ur / no match |
| 2018/CVE-2018-8006.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/admin/queues.jsp?Queue / no match |
| 2018/CVE-2018-8715.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/ status=200 / no match |
| 2018/CVE-2018-8719.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/uploads/wp- / no match |
| 2018/CVE-2018-8727.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/.../.../.../.../.../.. / no match |
| 2018/CVE-2018-8770.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/tests/generate.php sta / no match |
| 2018/CVE-2018-8823.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/modules/bamegamenu/aja / no match |
| 2018/CVE-2018-9118.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/wps / no match |
| 2018/CVE-2018-9161.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/user/scripts/login_par / no match |
| 2018/CVE-2018-9845.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Admin status=200 / no match |
| 2018/CVE-2018-9995.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/device.rsp?opt=user&cm / no match |
| 2017/CVE-2017-1000163.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?redirect=/\interact.s / no match |
| 2017/CVE-2017-1000170.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/wp-content/plugins/de / no match |
| 2017/CVE-2017-10075.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cs/idcplg?IdcService=G / no match |
| 2017/CVE-2017-11165.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/services/getFile.cmd?u / no match |
| 2017/CVE-2017-11444.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/search/members/?id`%3D / no match |
| 2017/CVE-2017-11512.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/fosagent/repl/download / no match |
| 2017/CVE-2017-11629.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?c=api&m=data / no match |
| 2017/CVE-2017-12542.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/rest/v1/AccountService / no match |
| 2017/CVE-2017-12583.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/dokuwiki/doku.php?id=w / no match |
| 2017/CVE-2017-12637.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/scheduler/ui/js/ffffff / no match |
| 2017/CVE-2017-12794.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/create_user/?username= / no match |
| 2017/CVE-2017-14186.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/remote/loginredir?redi / no match |
| 2017/CVE-2017-14651.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/carbon/resources/add_c / no match |
| 2017/CVE-2017-15363.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/typo3conf/ext/restler/ / no match |
| 2017/CVE-2017-16894.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/.env status=200 / no match |
| 2017/CVE-2017-17736.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/CMSInstall/install.asp / no match |
| 2017/CVE-2017-18536.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/?author=1%3C%2Fscript% / no match |
| 2017/CVE-2017-3132.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/p/user/ftoken/activate / no match |
| 2017/CVE-2017-3528.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/OA_HTML/cabo/jsps/a.js / no match |
| 2017/CVE-2017-4011.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639 status=200 / no match |
| 2017/CVE-2017-5521.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/passwordrecovered.cgi? / no match |
| 2017/CVE-2017-5631.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login.php?mid=0&usr=ad / no match |
| 2017/CVE-2017-5868.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/__session_start__/%0aS / no match |
| 2017/CVE-2017-5982.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/image/image%3A%2F%2F%2 / no match |
| 2017/CVE-2017-6478.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/install/index.php?step / no match |
| 2017/CVE-2017-7391.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/magmi/web/ajax_gettime / no match |
| 2017/CVE-2017-7504.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/jbossmq-httpil/HTTPSe / no match |
| 2017/CVE-2017-7615.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/verify.php?id=1&confir / no match |
| 2017/CVE-2017-7855.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/webmail/?language=%22% / no match |
| 2017/CVE-2017-7921.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/system/deviceInfo?auth / no match |
| 2017/CVE-2017-8229.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/current_config/Sha1Acc / no match |
| 2017/CVE-2017-8917.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/index.php?option=com_f / no match |
| 2017/CVE-2017-9140.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/Telerik.ReportViewer.a / no match |
| 2017/CVE-2017-9791.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/integration/saveGangs / no match |
| 2017/CVE-2017-9965.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/portal//..\\\..\\\..\\ / no match |
| 2016/CVE-2016-0957.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/system/console?.css st / no match |
| 2016/CVE-2016-10134.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/jsrpc.php?type=0&mode= / no match |
| 2016/CVE-2016-10367.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/monitoring/..%252f..%2 / no match |
| 2016/CVE-2016-10924.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/wp-content/plugins/ebo / no match |
| 2016/CVE-2016-10960.py | pass | vuln+safe | matched POST on http://127.0.0.1:43639/wp-content/plugins/ws / no match |
| 2016/CVE-2016-3978.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/login?redir=http://www / no match |
| 2016/CVE-2016-4975.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/~user/%0D%0ASet-Cookie / no match |
| 2016/CVE-2016-4977.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/oauth/authorize?respon / no match |
| 2016/CVE-2016-6195.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/forumrunner/request.ph / no match |
| 2016/CVE-2016-7552.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/cgi-bin/logoff.cgi sta / no match |
| 2016/CVE-2016-7834.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/command/prima-factory. / no match |
| 2016/CVE-2016-8527.py | pass | vuln+safe | matched GET on http://127.0.0.1:43639/visualrf/group_list.xm / no match |
| supplement/CVE-2021-26084.py | pass | vuln+safe | OGNL arithmetic oracle matched on http://127.0.0.1:43639/pag / no match |
| supplement/CVE-2022-26134.py | pass | vuln+safe | OGNL exec proof: X-Cmd-Response header echoed command output / no match |
| supplement/CVE-2023-34362.py | pass | vuln+safe | error-based signal: single-quote probe on folder_add_by_path / no SQL error signal from single-quote pr |
| supplement/CVE-2023-4966.py | pass | vuln+safe | memory-leak proof: leaked 124-byte session token + valid Get / no leaked session-token entropy in respo |
| supplement/CVE-2021-44228.py | param-warn-pass | no-param->WARN |  |
| supplement/CVE-2022-22965.py | param-warn-pass | no-param->WARN |  |
| supplement/CVE-2020-14882.py | param-warn-pass | no-param->WARN |  |
| supplement/CVE-2021-26855.py | param-warn-pass | no-param->WARN |  |
