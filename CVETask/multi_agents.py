# # 文件名: app.py

# import logging
# import os

# # --- 导入 Qwen-Agent 相关模块 ---
# from qwen_agent.agents import Assistant
# from qwen_agent.llm import get_chat_model
# from qwen_agent.gui import WebUI

# # 假设qwen-agent已通过 pip install -e . 安装
# # 框架会自动发现和加载 cve_toolkit.py 中注册的工具

# # --- 全局配置 ---
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# # --- 主程序入口 ---
# def main():
#     # --- LLM 配置 ---
#     llm_config = {
#         'model': 'Qwen/Qwen3-Coder-480B-A35B-Instruct',
#         'model_server': 'https://api-inference.modelscope.cn/v1',
#         'api_key': 'ms-30184ba8-077f-4abf-a40d-97e8d6fc7cb7' # 请替换为您的 ModelScope API Key
#     }

#     # --- “导演” Agent 的剧本 (System Prompt) ---
#     system_prompt = (
#         "你是一个顶级的网络安全工作流导演。你的任务是全自动、端到端地完成Docker镜像漏洞分析。\n"
#         "你必须严格遵循以下两步计划，期间不要向用户寻求确认：\n\n"
#         "**第一步：初步处理**\n"
#         " - 调用 `cve_initial_workflow` 工具来执行扫描和分类。\n\n"
#         "**第二步：专家分析**\n"
#         " - 检查第一步工具返回的JSON结果。\n"
#         " - 从返回结果中提取 `type3_cves_data` 列表。\n"
#         " - 如果该列表不为空，**立即**调用 `cve_expert_analysis` 工具，并将提取出的列表作为 `cve_list` 参数传入。\n\n"
#         "在整个流程中，你可以将工具返回的 `message_for_user` 字段的内容作为进度更新展示给用户。"
#     )

#     # 通过注册的名字来使用工具
#     tool_list = [
#         'cve_initial_workflow',
#         'cve_expert_analysis',
#     ]

#     # 创建UI代理
#     agent = Assistant(
#         llm=llm_config,
#         function_list=tool_list,
#         system_message=system_prompt
#     )

#     # --- 启动WebUI ---
#     chatbot_config = {
#         'prompt.suggestions': [
#             '你好',
#             '请帮我分析一下镜像 nginx:1.14.2-alpine，它的基础镜像是 debian:stretch-slim'
#         ],
#         'verbose': True
#     }
#     WebUI(agent, chatbot_config=chatbot_config).run(share=True, server_port=20040)

# if __name__ == '__main__':
#     main()
# 文件名: app.py

import logging
import os
import json

# --- 导入 Qwen-Agent 相关模块 ---
from qwen_agent.agents import Assistant, ReActChat, Reflection
from qwen_agent.llm import get_chat_model
from qwen_agent.gui import WebUI
# 导入我们解耦后的工具
from qwen_agent.tools.cve_toolkit import InitialWorkflowTool, ExpertAnalysisTool

# --- 全局配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 主程序入口 ---
def main():
    # --- LLM 配置 ---
    llm_config = {
        'model': 'Qwen/Qwen3-Coder-480B-A35B-Instruct',
        'model_server': 'https://api-inference.modelscope.cn/v1',
        'api_key': 'ms-df44f694-9197-4fff-beaf-677b6bdc5e1b' # 请替换为您的 ModelScope API Key
    }
    llm = get_chat_model(llm_config)

    # --- 【核心】在此处组装所有组件 ---

    # 1. 组建 Reflection 专家团队
    t3_generator = ReActChat(
        llm=llm_config,
        name='CVE分析员',
        # system_message= "请你在开始执行所有操作之前，输出你的执行计划。",
        system_message= f"""
            请严格按以下JSON格式分析CVE漏洞、回答、输出内容：
            {{
                "risk_level": "高/中/低",
                "whether_relevant" :"是否与目标镜像的使用有关，回答：Yes/No",
                "analysis": "影响分析, 是否会影响到被分析镜像的使用等",
                "suggestion": "修复建议",
                "workaround": "临时解决方案(如无则留空)"
            }}
            """,
        description="我是一个用来解决CVE漏洞检测的专家，我将帮助用户根据CVE扫描结果查找相关资料，补充相关信息，来通过CVE漏洞检测。"
    )
    t3_reflector = Assistant(
        llm=llm_config,
        name='CVE审核员',
        system_message= "你将就gerator给出的结论提出你的修改意见。请用以下格式回答问题，可信度：（回答可信或者不可信），修改意见：给出相关的意见。",
                        description="我是一个CVE漏洞检测的审核专家，我将审核generator给出的结论，并且根据generator的结论,给出看法和意见。"
    )
    expert_team = Reflection(
        name='CVE专家小组',
        llm=llm_config,
        agents=[t3_generator, t3_reflector]
    )

    # 2. 实例化两个阶段性工具，并将专家团队“注入”到第二个工具中
    initial_tool = InitialWorkflowTool()
    expert_tool = ExpertAnalysisTool(llm=llm, expert_team=expert_team)

    # 3. 定义“导演” Agent 的剧本
    system_prompt = (
        "你是一个顶级的网络安全工作流导演。你的任务是全自动、端到端地完成Docker镜像漏洞分析。\n"
        "你必须严格遵循以下两步计划，期间不要向用户寻求确认：\n\n"
        "**第一步：初步处理**\n"
        " - 调用 `cve_initial_workflow` 工具来执行扫描和分类。\n\n"
        "**第二步：专家分析**\n"
        " - 检查第一步工具返回的JSON结果。\n"
        " - 从返回结果中提取 `type3_cves_data` 列表。\n"
        " - 如果该列表不为空，**立即**调用 `cve_expert_analysis` 工具，并将提取出的列表作为 `cve_list` 参数传入。\n\n"
        "在整个流程中，你可以将工具返回的 `message_for_user` 字段的内容作为进度更新展示给用户。"
        "你在处理前，先把你的计划打出来，比如分哪几步做;在处理过程中可以把处理到哪一步等也打出来，让用户了解"

    )


    # 4. 创建最终的“导演” Agent，并将【实例化的工具】传递给它
    # 注意：因为我们的工具需要复杂初始化，所以直接传递实例而不是字符串名字
    director_toollist = [
        initial_tool,
        expert_tool,
        {
            'mcpServers': {  # You can specify the MCP configuration file
                'time': {
                    'command': 'uvx',
                    'args': ['mcp-server-time', '--local-timezone=Asia/Shanghai'],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
                'fetch': {
                    'command': 'uvx',
                    'args': ['mcp-server-fetch'],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911" 
                    }
                },
                "memory": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-memory"],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911",
                        "MEMORY_FILE_PATH": "/home/intel/chennan/Qwen-Agent/CVETask/workspace/doc/memory.json"
                    }
                },
                "sqlite" : {
                    "command": "uvx",
                    "args": [
                        "mcp-server-sqlite",
                        "--db-path",
                        "test.db"
                    ],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
                "filesystem": {
                    "command": "docker",
                    "args": [
                        "run",
                        "-i",
                        "--rm",
                        "--mount", "type=bind,src=/tmp,dst=/tmp",
                        "--mount", "type=bind,src=/home/intel/chennan,dst=/home/intel/chennan",
                        "mcp/filesystem",
                        "/home/intel/chennan"
                    ],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
            }
        }
    ]
    director_agent = Assistant(
        llm=llm,
        function_list=director_toollist,
        system_message=system_prompt
    )

    # --- 启动WebUI ---
    chatbot_config = {
        'prompt.suggestions': [
            '你好',
            '请帮我分析一下镜像 nginx:1.14.2-alpine，它的基础镜像是 debian:stretch-slim'
        ],
        'verbose': True
    }
    WebUI(director_agent, chatbot_config=chatbot_config).run(share=True, server_port=20040)

if __name__ == '__main__':
    main()