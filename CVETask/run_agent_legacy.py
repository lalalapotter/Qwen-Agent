import csv
import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Union
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
# --- Correct imports based on the provided qwen-agent source ---
from qwen_agent.agents import Assistant
from qwen_agent.llm import get_chat_model
from qwen_agent.tools.base import BaseTool
from qwen_agent.gui import WebUI
# --- 1. Global Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
WORKSPACE = os.path.join(os.getcwd(), 'workspace/doc')
os.makedirs(os.path.join(WORKSPACE, 'reports'), exist_ok=True)

# --- 2. Custom Tools for the Agent ---
class TrivyScanner(BaseTool):
    name = "trivy_scanner"
    description = "Runs a Trivy vulnerability scan on a Docker image and saves the output as a JSON file."
    parameters = [{
        'name': 'image_name',
        'type': 'string',
        'description': 'The full name of the Docker image to scan (e.g., \'python:3.9-slim\')',
        'required': True
    }]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        """Executes the Trivy scan and outputs to JSON."""
        try:
            params = self._verify_json_format_args(params)
            image_name = params['image_name']
        except Exception as e:
            return f"Parameter error: {e}"
        sanitized_name = image_name.replace(':', '_').replace('/', '_')
        output_path = os.path.join(WORKSPACE, f'{sanitized_name}_cves.json')
        command = ['trivy', 'image', '--format', 'json', '--output', output_path, image_name]
        logging.info(f"Running Trivy scan for {image_name}...")
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            success_message = f"Successfully scanned image '{image_name}'. Results saved to: {output_path}"
            logging.info(success_message)
            return success_message
        except FileNotFoundError:
            return "Error: 'trivy' command not found. Please ensure Trivy is installed and in your system PATH."
        except subprocess.CalledProcessError as e:
            return f"Error: Trivy scan failed for '{image_name}'. Stderr: {e.stderr}"

class JsonToCsvConverter(BaseTool):
    name = "json_to_csv_converter"
    description = "Converts a Trivy JSON report file to a CSV file with the required columns."
    parameters = [{
        'name': 'json_file_path',
        'type': 'string',
        'description': 'The path to the input JSON file from a Trivy scan.',
        'required': True
    }]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        """Converts Trivy JSON to our target CSV format."""
        try:
            params = self._verify_json_format_args(params)
            json_file_path = params['json_file_path']
        except Exception as e:
            return f"Parameter error: {e}"
        if not os.path.exists(json_file_path):
            return f"Error: Input file not found at {json_file_path}"
        csv_file_path = json_file_path.replace('.json', '.csv')
        
        headers = [
            "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", 
            "Severity", "Title", "Description", "PrimaryURL"
        ]
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f_json, \
                 open(csv_file_path, 'w', encoding='utf-8', newline='') as f_csv:
                
                writer = csv.DictWriter(f_csv, fieldnames=headers)
                writer.writeheader()
                data = json.load(f_json)
                
                if 'Results' not in data:
                    logging.warning(f"No 'Results' key found in {json_file_path}. The file might be empty or in an unexpected format.")
                    return f"Successfully created an empty CSV report at {csv_file_path} as no vulnerabilities were found."
                
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        writer.writerow({
                            "VulnerabilityID": vuln.get("VulnerabilityID", ""),
                            "PkgName": vuln.get("PkgName", ""),
                            "InstalledVersion": vuln.get("InstalledVersion", ""),
                            "FixedVersion": vuln.get("FixedVersion", ""),
                            "Severity": vuln.get("Severity", ""),
                            "Title": vuln.get("Title", ""),
                            "Description": vuln.get("Description", "").replace('\n', ' '), # Avoid newlines in CSV cells
                            "PrimaryURL": vuln.get("PrimaryURL", "")
                        })
            
            return f"Successfully converted {json_file_path} to {csv_file_path}"
        except Exception as e:
            return f"Error during JSON to CSV conversion: {e}"

# --- [新增] 修复问题的关键：CVE 分类工具 ---
class CVEClassifier(BaseTool):
    name = "cve_classifier"
    description = "Reads two CVE CSV reports (target and base), classifies the vulnerabilities into Type-1, Type-2, and returns a list of Type-3 CVEs for further analysis."
    parameters = [
        {
            'name': 'target_csv_path',
            'type': 'string',
            'description': 'The file path of the CSV report for the target image.',
            'required': True
        },
        {
            'name': 'base_csv_path',
            'type': 'string',
            'description': 'The file path of the CSV report for the base image.',
            'required': True
        }
    ]

    def call(self, params: Union[str, dict], **kwargs) -> Dict:
        """
        Reads CSVs, classifies CVEs, and returns a dictionary with the results.
        The agent will then use this dictionary for the next steps.
        """
        try:
            params = self._verify_json_format_args(params)
            target_csv_path = params['target_csv_path']
            base_csv_path = params['base_csv_path']
        except Exception as e:
            return {"error": f"Parameter error: {e}"}

        def read_cves_from_csv(file_path: str) -> Dict[str, dict]:
            cves = {}
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        # 使用正确的列标题 "VulnerabilityID"
                        cve_id = row.get("VulnerabilityID")
                        if cve_id:
                            cves[cve_id] = row
            except FileNotFoundError:
                logging.error(f"File not found: {file_path}")
                return {}
            except Exception as e:
                logging.error(f"Error reading CSV {file_path}: {e}")
                return {}
            return cves

        target_cves = read_cves_from_csv(target_csv_path)
        base_cves = read_cves_from_csv(base_csv_path)
        base_cve_ids = set(base_cves.keys())

        type1_cves = []
        type2_cves = []
        type3_cves_to_analyze = []

        for cve_id, cve_data in target_cves.items():
            if not cve_data.get("FixedVersion"):
                type1_cves.append(cve_data)
            elif cve_id in base_cve_ids:
                type2_cves.append(cve_data)
            else:
                type3_cves_to_analyze.append(cve_data)
        
        result = {
            "type1_cves": type1_cves,
            "type2_cves": type2_cves,
            "type3_cves_to_analyze": type3_cves_to_analyze
        }
        
        summary = (
            f"Successfully classified CVEs. "
            f"Found {len(type1_cves)} Type-1, "
            f"{len(type2_cves)} Type-2, and "
            f"{len(type3_cves_to_analyze)} Type-3 vulnerabilities for analysis."
        )
        logging.info(summary)
        
        # 将结构化数据返回给 Agent，它将在下一步中使用这些数据
        return result


import os
from datetime import datetime
from pathlib import Path
import json
from typing import Union, Dict, List
from concurrent.futures import ThreadPoolExecutor

# (确保您已经导入了 BaseTool 和 logging)
# from qwen_agent.tools.base import BaseTool
# import logging

class CVEReportGenerator(BaseTool):
    name = "cve_report_generator"
    description = "根据分类后的 CVE 列表，生成多个 trivyignore YAML 文件和一份建议报告。"
    parameters = [{
        'name': 'classified_cves',
        'type': 'Union[str, dict]',
        'description': '包含 CVE 列表的 JSON 字符串或字典，键为: type1_cves, type2_cves, type3_results',
        'required': True
    }]

    def _verify_and_normalize_params(self, params: Union[str, dict]) -> dict:
        """增强的参数验证与详细的错误消息"""
        try:
            # 第一步：统一将输入转为字典
            if isinstance(params, str):
                try:
                    params = json.loads(params)  # 先解析外层JSON
                except json.JSONDecodeError as e:
                    raise ValueError(f"无效的 JSON 字符串: {str(e)}")

            if not isinstance(params, dict):
                raise ValueError(f"期望是字典或 JSON 字符串，但得到的是 {type(params)}")

            # 第二步：提取 classified_cves 并处理嵌套的JSON字符串
            cves_data = params.get('classified_cves', params)
            if isinstance(cves_data, str):
                try:
                    cves_data = json.loads(cves_data)  # 解析嵌套的JSON
                except json.JSONDecodeError as e:
                    raise ValueError(f"classified_cves 内的 JSON 无效: {str(e)}")

            # 第三步：验证数据结构
            if not isinstance(cves_data, dict):
                raise ValueError(f"classified_cves 应是字典，但得到的是 {type(cves_data)}")

            normalized = {
                'type1_cves': cves_data.get('type1_cves', []),
                'type2_cves': cves_data.get('type2_cves', []),
                'type3_results': cves_data.get('type3_results', [])
            }
            if not all(isinstance(v, list) for v in normalized.values()):
                raise ValueError("所有的 CVE 列表都必须是数组类型")
            return normalized

        except Exception as e:
            logging.error(f"参数验证失败: {e}\n输入内容为: {str(params)[:200]}...")
            raise

    def _write_ignore_file(self, file_path: Path, ignore_list: List[Dict], header_comment: str):
        """一个通用的函数，用于写入 trivyignore 文件"""
        if not ignore_list:
            logging.info(f"忽略列表为空，跳过生成文件: {file_path}")
            return 0
            
        file_path.parent.mkdir(exist_ok=True, parents=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"# {header_comment}\n")
            f.write("# This file was auto-generated by Qwen-Agent\n")
            f.write(f"# Generation Time: {datetime.now().isoformat()}\n")
            f.write("vulnerabilities:\n")
            for entry in ignore_list:
                f.write(f"- id: {entry['id']}\n")
                f.write(f"  url: {entry['url']}\n")
                f.write(f"  statement: {entry['reason']}\n")
        return len(ignore_list)

    def call(self, params: Union[str, dict], **kwargs) -> str:
        """为每一类 CVE 生成独立的 trivyignore 文件和最终的建议报告"""
        debug_dir = Path(WORKSPACE) / "debug"
        debug_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        debug_file = debug_dir / f"report_input_{timestamp}.json"
        
        try:
            print("Opening")
            with open(debug_file, 'w', encoding='utf-8') as f:
                print("Opened")
                json.dump(params if isinstance(params, dict) else {"raw_input": params},
                            f, indent=2, ensure_ascii=False)
            classified_cves = self._verify_and_normalize_params(params)
            
            # --- 分类处理并写入不同文件 ---
            
            # 1. 处理 Type-1
            type1_ignores = [
                {'id': cve.get('VulnerabilityID', ''),'url':cve.get('PrimaryURL','') ,'reason': "There is currently no recommended version available to fix this vulnerability. We will continue to monitor for updates and apply a fix once it is released."}
                for cve in classified_cves['type1_cves'] if cve.get('VulnerabilityID')
            ]
            count1 = self._write_ignore_file(
                Path(WORKSPACE) / 'trivyignore-type1.yaml',
                type1_ignores,
                "There is currently no recommended version available to fix this vulnerability. We will continue to monitor for updates and apply a fix once it is released."
            )

            # 2. 处理 Type-2
            type2_ignores = [
                {'id': cve.get('VulnerabilityID', ''),'url':cve.get('PrimaryURL','') , 'reason': "The affected package is not used directly by our application. It comes from the underlying base image. We will continue to monitor and adopt a newer base image if one becomes available that resolves this issue."}
                for cve in classified_cves['type2_cves'] if cve.get('VulnerabilityID')
            ]
            count2 = self._write_ignore_file(
                Path(WORKSPACE) / 'trivyignore-type2.yaml',
                type2_ignores,
                "The affected package is not used directly by our application. It comes from the underlying base image. We will continue to monitor and adopt a newer base image if one becomes available that resolves this issue."
            )

            # 3. 处理 Type-3 并生成建议
            type3_ignores = []
            suggestions = []
            for item in classified_cves['type3_results']:
                try:
                    cve = item.get('cve', {})
                    analysis = item.get('analysis', {})
                    cve_id = cve.get('VulnerabilityID', 'N/A')
                    pkg_name = cve.get('PkgName', 'N/A')
                    cve_url = cve.get('PrimaryURL','') 

                    # 所有经过分析的 Type-3 漏洞都应该被记录
                    if analysis.get('reason'):
                        type3_ignores.append({
                            'id': cve_id,
                            'url': cve_url,
                            'reason': f"Type-3: {analysis.get('reason', 'No specific reason provided.')}"
                        })

                    if suggestion := analysis.get('suggestion'):
                        suggestions.append(f"[{cve_id}/{pkg_name}]: {suggestion}")
                
                except Exception as e:
                    logging.warning(f"Skipping malformed Type-3 entry: {str(e)}")
                    continue

            count3 = self._write_ignore_file(
                Path(WORKSPACE) / 'trivyignore-type3.yaml',
                type3_ignores,
                "Type-3 CVEs: Manually analyzed by Agent"
            )
            
            # --- 写入建议报告 ---
            report_path = Path(WORKSPACE) / 'reports' / 'upgrade_patch_suggestions.txt'
            report_path.parent.mkdir(exist_ok=True, parents=True)
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("来自 Type-3 分析的升级/补丁建议\n" + "=" * 50 + "\n")
                if suggestions:
                    f.writelines(f"{s}\n\n" for s in suggestions)
                else:
                    f.write("没有需要应用补丁或升级的建议。\n")

            return (
                f"报告生成完成。\n"
                f"- 生成了 {count1} 条 Type-1 忽略规则在 trivyignore-type1.yaml\n"
                f"- 生成了 {count2} 条 Type-2 忽略规则在 trivyignore-type2.yaml\n"
                f"- 生成了 {count3} 条 Type-3 忽略规则在 trivyignore-type3.yaml\n"
                f"- 在 {report_path} 中创建了 {len(suggestions)} 条建议\n"
                f"调试输入已保存至: {debug_file}"
            )

        except Exception as e:
            logging.exception("报告生成失败")
            return f"错误: {str(e)}\n调试数据已保存至: {debug_file}"

# --- 3. Main Execution Logic ---
def main():
    # --- LLM Configuration ---
    # !! IMPORTANT !!: Replace 'model_server' with your VLLM service URL.
    llm_config = {
        'model': 'Qwen/Qwen3-Coder-480B-A35B-Instruct',  # This can be a placeholder
        'model_server': 'https://api-inference.modelscope.cn/v1',  # URL for the OpenAI-compatible API
        'api_key': 'xxxx'  # Not needed for local VLLM
    }
    # llm_config = {
    #     'model': '/llm/models/Qwen3-30B-A3B',  # This can be a placeholder
    #     'model_server': 'http://localhost:8001/v1',  # URL for the OpenAI-compatible API
    #     'api_key': 'EMPTY'  # Not needed for local VLLM
    # }
    llm = get_chat_model(llm_config)
    
    # --- [更新] 修复问题的关键：更清晰的系统提示 ---
    system_prompt = """
    You are an intelligent cybersecurity assistant. Your mission is to automate the processing of CVE vulnerabilities in a Docker image.
    You must strictly follow these steps and call the tools in sequence:
    1.  **Scan Images**: Use the `trivy_scanner` tool to scan the user-provided target image and base image. This will produce two JSON files.
    2.  **Convert Reports**: Use the `json_to_csv_converter` tool for each of the two JSON files to convert them into CSV format.
    3.  **Classify CVEs**: Call the `cve_classifier` tool ONCE, passing the file paths of the two CSVs you just created. This tool will do the classification and return structured data containing lists of 'type1_cves', 'type2_cves', and 'type3_cves_to_analyze'.
    4.  **Analyze Type-3 CVEs**: The previous step gave you a list of Type-3 CVEs. Now, you must act as a security expert. For EACH AND EVERY CVE in the 'type3_cves_to_analyze' list, generate a JSON object with your analysis. The format for each analysis must be: `{"cve": {... a dict containing the original CVE data ...}, "analysis": {"action": "ignore" | "suggest_patch", "reason": "...determine whether the CVE is relevant to the image,if not, the image not impacted by this issue,if yes, give the reason and some details...", "suggestion": "..." | null}}`.
    5.  **Generate Final Report**: After analyzing all Type-3 CVEs, call the `cve_report_generator` tool exactly ONCE. You will construct its `classified_cves` parameter as follows:
        - The 'type1_cves' key should contain the list of Type-1 CVEs from step 3.
        - The 'type2_cves' key should contain the list of Type-2 CVEs from step 3.
        - The 'type3_results' key should contain the list of your analysis JSON objects from step 4.
    6.  **Conclude**: After the report is generated successfully, inform the user that the task is complete and state the location of the output files.
    """
    
    # --- [更新] 修复问题的关键：添加新工具到列表 ---
    # tool_list = [TrivyScanner(), JsonToCsvConverter(), CVEClassifier(), CVEReportGenerator()]
    tool_list = [
        TrivyScanner(),
        JsonToCsvConverter(),
        CVEClassifier(),
        CVEReportGenerator(),
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
        # 'code_interpreter',  # Built-in tools
    ]
    agent = Assistant(llm=llm, function_list=tool_list, system_message=system_prompt)
    
    # --- User's Task Request ---
    target_image = 'nginx:1.14.2-alpine'
    base_image = 'debian:stretch-slim'
    user_query = (
        f"Please start processing the CVEs for a Docker image. The target image is '{target_image}', "
        f"and its base image is '{base_image}'."
    )
    messages = [{'role': 'user', 'content': user_query}]


    chatbot_config = {
        'prompt.suggestions': [
            'What time is it?',
            'https://github.com/orgs/QwenLM/repositories Extract markdown content of this page, then draw a bar chart to display the number of stars.'
        ],
        'verbose': True
    }
    WebUI(
        agent,
        chatbot_config=chatbot_config,
    ).run()
    
    # # Run the agent
    # for response in agent.run(messages=messages):
    #     print("--------------- Agent Response ---------------")
    #     print(response)

if __name__ == '__main__':
    main()