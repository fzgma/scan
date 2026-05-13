# ui/app.py
import streamlit as st

from scanner.scanner import scan


def run_app():
    """
    Streamlit 页面入口函数。
    负责用户输入、调用扫描逻辑、展示检测结果。
    """

    # 页面基础配置
    st.set_page_config(
        page_title="WebGuardian 网站安全检测工具",
        layout="centered"
    )

    st.title("WebGuardian 网站安全检测工具")
    st.caption("输入网站地址后，系统将进行基础安全检测并生成评分结果。")

    # 用户输入区域
    url = st.text_input(
        "请输入网站地址",
        placeholder="例如：https://example.com"
    )

    # 点击按钮后开始检测
    if st.button("开始检测", type="primary"):
        if not url.strip():
            st.warning("请先输入网站地址。")
            return

        # 调用 scanner 层进行检测
        with st.spinner("正在检测，请稍候..."):
            result = scan(url)

        # 如果检测入口校验失败，则直接展示错误信息
        if not result.get("ok"):
            st.error(f"检测失败：{result.get('error', '未知错误')}")
            return

        # 展示核心评分信息
        st.subheader("检测结果概览")

        col1, col2, col3 = st.columns(3)
        col1.metric("安全评分", f"{result['score']}/100")
        col2.metric("安全等级", result["level"])
        col3.metric("HTTPS", "是" if result["https"] else "否")

        st.divider()

        # 展示基础信息
        st.subheader("基础信息")
        st.write("检测地址：", result["url"])
        st.write("主机名称：", result["host"])

        st.divider()

        # TLS/SSL 检测结果
        st.subheader("TLS/SSL 检测")

        st.write("SSL 证书有效：", "是" if result["ssl_valid"] else "否")

        if result["ssl_valid"]:
            st.write("证书剩余天数：", result["ssl_days_left"])
        else:
            st.warning("未检测到有效的 SSL 证书，或证书检测失败。")

        st.divider()

        # HTTP 安全响应头检测结果
        st.subheader("HTTP 安全头检测")

        st.write("安全头得分：", result["security_header_score"])

        if result["missing_security_headers"]:
            st.warning("存在缺失的安全响应头：")
            st.code("\n".join(result["missing_security_headers"]))
        else:
            st.success("未发现缺失的安全响应头。")

        st.divider()

        # TRACE 方法检测
        st.subheader("TRACE 方法检测")

        if result["trace_enabled"]:
            st.error("TRACE 方法已启用，存在一定安全风险。")
        else:
            st.success("TRACE 方法未启用。")

        st.divider()

        # 敏感路径检测
        st.subheader("敏感路径检测")

        if result["sensitive_paths"]:
            st.warning("发现可能存在的敏感路径：")
            st.code("\n".join(result["sensitive_paths"]))
        else:
            st.success("未发现常见敏感路径。")

        st.divider()

        # 端口检测
        st.subheader("端口检测")

        if result["open_ports"]:
            st.write("开放端口：", result["open_ports"])
        else:
            st.write("未发现开放的常见端口。")

        st.divider()

        # 信息泄露检测
        st.subheader("信息泄露检测")

        info_leak = result.get("info_leak", {})

        server_header_exists = info_leak.get("server_header_exists")
        x_powered_by_exists = info_leak.get("x_powered_by_exists")

        if server_header_exists is True:
            st.warning("响应头中存在 Server 字段，可能泄露服务器信息。")
        elif server_header_exists is False:
            st.success("响应头中未发现 Server 字段。")
        else:
            st.info("Server 字段未检测。")

        if x_powered_by_exists is True:
            st.warning("响应头中存在 X-Powered-By 字段，可能泄露技术栈信息。")
        elif x_powered_by_exists is False:
            st.success("响应头中未发现 X-Powered-By 字段。")
        else:
            st.info("X-Powered-By 字段未检测。")

        # 展示部分异常，但不中断整体结果
        if result.get("errors"):
            st.divider()
            st.subheader("检测过程提示")
            st.warning("部分检测项执行异常，结果可能不完整：")
            for error in result["errors"]:
                st.write(f"- {error}")

        st.divider()

        # 原始数据展示，便于调试和后续扩展
        with st.expander("查看原始检测结果"):
            st.json(result)


if __name__ == "__main__":
    run_app()
