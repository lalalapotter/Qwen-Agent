import csv
import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Union, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re
import time
# --- 导入 Qwen-Agent 相关模块 ---
from qwen_agent.agents import Assistant
from qwen_agent.llm import get_chat_model
from qwen_agent.llm.schema import Message
from qwen_agent.tools.base import BaseTool
from qwen_agent.gui import WebUI
from qwen_agent.tools.cve_workflow import CVEWorkflowTool
# --- 1. 全局配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
WORKSPACE = os.path.join(os.getcwd(), 'workspace/doc')
os.makedirs(os.path.join(WORKSPACE, 'reports'), exist_ok=True)
os.makedirs(os.path.join(WORKSPACE, 'debug'), exist_ok=True)


# --- 2. 核心工具类 (与之前相同) ---
# TrivyScanner, JsonToCsvConverter, CVEClassifier, CVEReportGenerator 这四个类的代码
# 和我们之前版本完全一样，这里为了简洁先折叠起来，您直接使用上一版本即可。
# (在下面的完整代码块中我会全部展开)

# --- 5. 主程序入口 ---
def main():
    # --- LLM 配置 ---
    llm_config = {
        'model': 'Qwen/Qwen3-Coder-480B-A35B-Instruct',
        'model_server': 'https://api-inference.modelscope.cn/v1',
        'api_key': 'ms-30184ba8-077f-4abf-a40d-97e8d6fc7cb7' # 请替换为您的 ModelScope API Key
    }
    llm = get_chat_model(llm_config)

    # --- 创建主交互代理 ---
    # 这个代理很简单，它的任务就是理解用户意图，并调用我们的 CVEWorkflowTool
    # system_prompt = """
    # You are an intelligent cybersecurity assistant. Your mission is to automate the processing of CVE vulnerabilities in a Docker image.
    # You must strictly follow these steps and call the tools in sequence:
    # 1.  **Scan Images**: Use the `trivy_scanner` tool to scan the user-provided target image and base image. This will produce two JSON files.
    # 2.  **Convert Reports**: Use the `json_to_csv_converter` tool for each of the two JSON files to convert them into CSV format.
    # 3.  **Classify CVEs**: Call the `cve_classifier` tool ONCE, passing the file paths of the two CSVs you just created. This tool will do the classification and return structured data containing lists of 'type1_cves', 'type2_cves', and 'type3_cves_to_analyze'.
    # 4.  **Analyze Type-3 CVEs**: The previous step gave you a list of Type-3 CVEs. Now, you must act as a security expert. For EACH AND EVERY CVE in the 'type3_cves_to_analyze' list, generate a JSON object with your analysis. The format for each analysis must be: `{"cve": {... a dict containing the original CVE data ...}, "analysis": {"action": "ignore" | "suggest_patch", "reason": "...determine whether the CVE is relevant to the image,if not, the image not impacted by this issue,if yes, give the reason and some details...", "suggestion": "..." | null}}`.
    # 5.  **Generate Final Report**: After analyzing all Type-3 CVEs, call the `cve_report_generator` tool exactly ONCE. You will construct its `classified_cves` parameter as follows:
    #     - The 'type1_cves' key should contain the list of Type-1 CVEs from step 3.
    #     - The 'type2_cves' key should contain the list of Type-2 CVEs from step 3.
    #     - The 'type3_results' key should contain the list of your analysis JSON objects from step 4.
    # 6.  **Conclude**: After the report is generated successfully, inform the user that the task is complete and state the location of the output files.
    # """
    system_prompt = (
        "你是一个智能网络安全助手。"
        "当用户需要分析Docker镜像漏洞时，请使用 `cve_workflow_tool` 工具来完成任务。"
        "你需要从用户处获取 `target_image` 和 `base_image` 的名称。"
        "如果缺少信息，请向用户提问。"
    )
    # 将llm实例传入我们的大工具
    cve_workflow = CVEWorkflowTool(llm=llm)
    tool_list = [
        cve_workflow,
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
                        "https_proxy": "http://proxy.iil.intel.com:911"
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
                # "Trivy MCP": {
                #     "command": "/home/intel/cengguang/trivy",
                #     "args": [
                #         "mcp",  
                #         "--trivy-binary",  
                #         "/home/intel/cengguang/trivy",  
                #         "-t",  
                #         "stdio",  
                #         "-p",  
                #         "23456"  
                #     ],
                #     'env':{
                #         "http_proxy": "http://proxy.iil.intel.com:911",
                #         "https_proxy": "http://proxy.iil.intel.com:911"
                #     }
                # },
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
    # 创建UI代理
    agent = Assistant(
        llm=llm,
        function_list=tool_list,
        system_message=system_prompt
    )

    # --- 启动WebUI ---
    # 预设一些用户可能点击的示例问题
    chatbot_config = {
        'prompt.suggestions': [
            '你好',
            '请帮我分析一下镜像 nginx:1.14.2-alpine，它的基础镜像是 debian:stretch-slim'
        ],
        'verbose': True
    }
    WebUI(agent, chatbot_config=chatbot_config).run(share=True,server_port=20040)

if __name__ == '__main__':
    main()