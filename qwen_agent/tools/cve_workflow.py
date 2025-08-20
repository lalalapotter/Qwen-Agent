# 文件路径: Qwen-Agent/qwen_agent/tools/cve_toolkit.py

import csv
import json
import logging
import os
import subprocess
import re
import time
from datetime import datetime
from typing import Dict, List, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# 【重要】从框架导入 BaseTool 和 register_tool
from .base import BaseTool, register_tool
from ..llm import BaseChatModel

# --- 全局配置 ---
WORKSPACE = os.path.join(os.getcwd(), 'workspace/doc')
# 在工具加载时确保目录存在
os.makedirs(os.path.join(WORKSPACE, 'reports'), exist_ok=True)
os.makedirs(os.path.join(WORKSPACE, 'debug'), exist_ok=True)


# --- 定义所有底层工具，并使用装饰器注册 ---

@register_tool('trivy_scanner')
class TrivyScanner(BaseTool):
    description = "对一个Docker镜像进行Trivy漏洞扫描，并将输出保存为JSON文件。"
    parameters = [{'name': 'image_name', 'type': 'string', 'description': '要扫描的Docker镜像全名', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        # ... 函数实现和之前完全一样 ...
        try:
            params = self._verify_json_format_args(params)
            image_name = params['image_name']
        except Exception as e: return f'{{"error": "Parameter error: {e}"}}'
        sanitized_name = image_name.replace(':', '_').replace('/', '_')
        output_path = os.path.join(WORKSPACE, f'{sanitized_name}_cves.json')
        command = ['trivy', 'image', '--format', 'json', '--output', output_path, image_name]
        logging.info(f"Running Trivy scan for {image_name}...")
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            return json.dumps({"output_path": output_path})
        except FileNotFoundError: return '{{"error": "Trivy command not found. Please ensure Trivy is installed."}}'
        except subprocess.CalledProcessError as e: return f'{{"error": "Trivy scan failed for \'{image_name}\'. Stderr: {e.stderr}"}}'

@register_tool('json_to_csv')
class JsonToCsvConverter(BaseTool):
    description = "将Trivy的JSON报告文件转换为CSV文件。"
    parameters = [{'name': 'json_file_path', 'type': 'string', 'description': 'Trivy扫描产生的JSON文件路径', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        # ... 函数实现和之前完全一样 ...
        try:
            params = self._verify_json_format_args(params)
            json_file_path = params['json_file_path']
        except Exception as e: return f'{{"error": "Parameter error: {e}"}}'
        if not os.path.exists(json_file_path): return f'{{"error": "Input file not found at {json_file_path}"}}'
        csv_file_path = json_file_path.replace('.json', '.csv')
        headers = ["VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Title", "Description", "PrimaryURL"]
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f_json, open(csv_file_path, 'w', encoding='utf-8', newline='') as f_csv:
                writer = csv.DictWriter(f_csv, fieldnames=headers)
                writer.writeheader()
                data = json.load(f_json)
                if 'Results' not in data: return json.dumps({"output_path": csv_file_path, "status": "empty"})
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []): writer.writerow({h: str(vuln.get(h, "")).replace('\n', ' ') for h in headers})
            return json.dumps({"output_path": csv_file_path})
        except Exception as e: return f'{{"error": "Error during JSON to CSV conversion: {e}"}}'

@register_tool('cve_classifier')
class CVEClassifier(BaseTool):
    description = "读取两个CVE CSV报告（目标和基础），对漏洞进行分类。"
    parameters = [{'name': 'target_csv_path', 'type': 'string', 'required': True}, {'name': 'base_csv_path', 'type': 'string', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> Dict:
        # ... 函数实现和之前完全一样 ...
        try:
            params = self._verify_json_format_args(params)
            target_csv_path, base_csv_path = params['target_csv_path'], params['base_csv_path']
        except Exception as e: return {"error": f"Parameter error: {e}"}
        def read_cves_from_csv(file_path: str) -> Dict[str, dict]:
            cves = {}
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if cve_id := row.get("VulnerabilityID"): cves[cve_id] = row
            except FileNotFoundError: return {}
            return cves
        target_cves, base_cves = read_cves_from_csv(target_csv_path), read_cves_from_csv(base_csv_path)
        base_cve_ids = set(base_cves.keys())
        type1_cves, type2_cves, type3_cves = [], [], []
        for cve_id, cve_data in target_cves.items():
            if not cve_data.get("FixedVersion"): type1_cves.append(cve_data)
            elif cve_id in base_cve_ids: type2_cves.append(cve_data)
            else: type3_cves.append(cve_data)
        return {"type1_cves": type1_cves, "type2_cves": type2_cves, "type3_cves_to_analyze": type3_cves}

@register_tool('cve_reporter')
class CVEReportGenerator(BaseTool):
    description = "根据分类后的CVE列表生成trivyignore文件和建议报告。"
    parameters = [{'name': 'classified_cves', 'type': 'dict', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        try:
            cves_data = self._verify_json_format_args(params).get('classified_cves', {})
            # ... (省略了写入文件的详细代码, 和之前一样) ...
            def _write_ignore_file(file_path: Path, ignore_list: List[Dict], header: str):
                if not ignore_list: return 0
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"# {header}\n# Auto-generated by Qwen-Agent\n")
                    f.write("vulnerabilities:\n")
                    for entry in ignore_list:
                        f.write(f"- id: {entry['id']}\n")
                        if entry.get('url'): f.write(f"  url: {entry['url']}\n")
                        f.write(f"  statement: {entry['reason']}\n")
                return len(ignore_list)
            
            type1_ignores = [{'id': c.get('VulnerabilityID', ''), 'url':c.get('PrimaryURL',''), 'reason': "There is currently no recommended version available to fix this vulnerability. We will continue to monitor for updates and apply a fix once it is released."} for c in cves_data.get('type1_cves', [])]
            count1 = _write_ignore_file(Path(WORKSPACE)/'trivyignore-type1.yaml', type1_ignores, "There is currently no recommended version available to fix this vulnerability. We will continue to monitor for updates and apply a fix once it is released.")

            type2_ignores = [{'id': c.get('VulnerabilityID', ''), 'url':c.get('PrimaryURL',''), 'reason': "The affected package is not used directly by our application. It comes from the underlying base image. We will continue to monitor and adopt a newer base image if one becomes available that resolves this issue."} for c in cves_data.get('type2_cves', [])]
            count2 = _write_ignore_file(Path(WORKSPACE)/'trivyignore-type2.yaml', type2_ignores, "The affected package is not used directly by our application. It comes from the underlying base image. We will continue to monitor and adopt a newer base image if one becomes available that resolves this issue.")

            type3_results = cves_data.get('type3_results', [])

            type3_ignores = [{'id': i.get('cve', {}).get('VulnerabilityID'), 'url': i.get('cve', {}).get('PrimaryURL'), 'reason': f"{i.get('analysis', {}).get('analysis', 'N/A')}"} for i in type3_results]
            count3 = _write_ignore_file(Path(WORKSPACE)/'trivyignore-type3.yaml', type3_ignores, "Analyzed by agent.")

            suggestions = [f"[{i.get('cve', {}).get('VulnerabilityID')}/{i.get('cve', {}).get('PkgName')}]: {i.get('analysis', {}).get('suggestion')}" for i in type3_results if i.get('analysis', {}).get('suggestion')]
            report_path = Path(WORKSPACE)/'reports'/'upgrade_patch_suggestions.txt'
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("Suggestions from Type-3 Analysis\n" + "="*50 + "\n")
                if suggestions: f.writelines(f"{s}\n\n" for s in suggestions)
                else: f.write("No actionable suggestions were generated.\n")
            
            return (f"报告生成完成。\n" f"- {count1}条Type-1规则 -> trivyignore-type1.yaml\n" f"- {count2}条Type-2规则 -> trivyignore-type2.yaml\n" f"- {count3}条Type-3规则 -> trivyignore-type3.yaml\n" f"- {len(suggestions)}条建议 -> {report_path}")
        except Exception as e:
            return f"报告生成失败: {e}"

# --- Type-3 分析辅助函数 (这个不是工具，所以不需要注册) ---
def call_llm_for_analysis(cve_data: dict, llm: BaseChatModel) -> dict:
    prompt = f"""
    请严格按以下JSON格式分析CVE漏洞：
    {{
        "risk_level": "高/中/低",
        "analysis": "影响分析, 是否会影响到被分析镜像的使用等",
        "suggestion": "修复建议",
        "workaround": "临时解决方案(如无则留空)"
    }}

    待分析CVE详情：
    CVE ID: {cve_data.get('VulnerabilityID', 'N/A')}
    软件包: {cve_data.get('PkgName', 'N/A')} 
    版本: {cve_data.get('InstalledVersion', 'N/A')}
    修复版本: {cve_data.get('FixedVersion', '暂无')}
    严重程度: {cve_data.get('Severity', 'N/A')}
    描述: {cve_data.get('Description', '无描述信息')}
    """

    max_retries = 5
    retry_delay = 1.5  # 适当增加延迟
    
    for attempt in range(max_retries):
        try:
            # 1. 调用API
            response = llm.chat(
                messages=[{'role': 'user', 'content': prompt}],
                stream=False
            )
            
            # 2. 验证响应格式
            if not (isinstance(response, list) and 
                   len(response) > 0 and 
                   isinstance(response[0], dict) and
                   'content' in response[0]):
                raise ValueError("响应格式不符合预期")
            
            # 3. 提取JSON内容
            content = response[0]['content']
            json_str = re.search(r'```json\n(.*?)\n```', content, re.DOTALL)
            
            if not json_str:
                # 尝试直接解析整个content
                try:
                    analysis = json.loads(content)
                except json.JSONDecodeError:
                    raise ValueError("未找到有效的JSON内容")
            else:
                analysis = json.loads(json_str.group(1))
            
            # 4. 验证必需字段
            required_fields = ["risk_level", "analysis", "suggestion"]
            for field in required_fields:
                if field not in analysis:
                    raise ValueError(f"缺少必需字段: {field}")
            print(analysis)
            return {
                "cve": cve_data,
                "analysis": analysis
            }
            
        except Exception as e:
            logging.warning(f"尝试 {attempt + 1}/{max_retries} 失败 (CVE-{cve_data.get('VulnerabilityID')}): {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))
                continue
            
            return {
                "cve": cve_data,
                "analysis": {
                    "error": f"分析失败: {str(e)}",
                    "raw_response": response[0]['content'][:500] if isinstance(response, list) and len(response) > 0 else str(response)[:500]
                }
            }


# --- 定义并注册最高级的工作流工具 ---
@register_tool('cve_workflow')
class CVEWorkflowTool(BaseTool):
    description = "为指定的Docker镜像启动一个完整的CVE分析工作流，是处理此类任务的首选工具。"
    parameters = [
        {'name': 'target_image', 'type': 'string', 'description': '需要分析的目标镜像', 'required': True},
        {'name': 'base_image', 'type': 'string', 'description': '用于对比的基础镜像', 'required': True}
    ]
    
    # 【重要】注意这里的 __init__ 变化
    def __init__(self, cfg: dict = None, llm: BaseChatModel = None):
        super().__init__(cfg)
        self.llm = llm # llm 实例会由框架自动传入
        # 直接实例化，因为它们都在同一个文件中
        self.scanner = TrivyScanner()
        self.converter = JsonToCsvConverter()
        self.classifier = CVEClassifier()
        self.reporter = CVEReportGenerator()
    
    def call(self, params: Union[str, dict], **kwargs) -> str:
        try:
            params = self._verify_json_format_args(params)
            target_image = params['target_image']
            base_image = params['base_image']
        except Exception as e:
            return f"❌ 参数错误: {e}"
        
        # 获取消息回调函数（用于实时更新）
        message_callback = kwargs.get('messages', None)
        
        def _send_update(msg: str):
            """辅助函数：发送更新消息"""
            if callable(message_callback):
                message_callback(msg)
        
        _send_update(f"🚀 **工作流启动**\n   - 目标镜像: `{target_image}`\n   - 基础镜像: `{base_image}`")
        
        try:
            # --- 步骤 1 & 2: 扫描和转换 ---
            _send_update("\n---\n**步骤 1/5: 扫描镜像中...** 🔍")
            target_scan_res = json.loads(self.scanner.call({'image_name': target_image}))
            if 'error' in target_scan_res: raise RuntimeError(target_scan_res['error'])
            base_scan_res = json.loads(self.scanner.call({'image_name': base_image}))
            if 'error' in base_scan_res: raise RuntimeError(base_scan_res['error'])
            
            _send_update(f"   - ✅ 扫描完成: `{target_scan_res['output_path']}`")
            _send_update("\n---\n**步骤 2/5: 转换报告为CSV...** 📄")
            target_csv_res = json.loads(self.converter.call({'json_file_path': target_scan_res['output_path']}))
            if 'error' in target_csv_res: raise RuntimeError(target_csv_res['error'])
            base_csv_res = json.loads(self.converter.call({'json_file_path': base_scan_res['output_path']}))
            if 'error' in base_csv_res: raise RuntimeError(base_csv_res['error'])
            _send_update(f"   - ✅ 转换完成: `{target_csv_res['output_path']}`")
            
            # --- 步骤 3: 分类 ---
            _send_update("\n---\n**步骤 3/5: 对比并分类CVE...** 🗂️")
            classification_result = self.classifier.call({
                'target_csv_path': target_csv_res['output_path'],
                'base_csv_path': base_csv_res['output_path']
            })
            if 'error' in classification_result: raise RuntimeError(classification_result['error'])
            
            type1_cves = classification_result.get('type1_cves', [])
            type2_cves = classification_result.get('type2_cves', [])
            type3_cves = classification_result.get('type3_cves_to_analyze', [])
            _send_update(f"   - ✅ 分类完成: 发现Type-1: {len(type1_cves)}, Type-2: {len(type2_cves)}, Type-3: {len(type3_cves)}")
            
            # --- 步骤 4: 并行AI分析 ---
            # 在 CVEWorkflowTool.call() 方法中修改并行处理部分：
            # 在CVEWorkflowTool中
            _send_update(f"\n---\n**步骤 4/5: 专业分析 {len(type3_cves)} 个关键漏洞...** 🔍")
            type3_analysis_results = []

            if type3_cves:
                # 精确控制请求速率
                max_concurrent = 2  # 进一步降低并发数
                request_interval = 2.0  # 请求间隔2秒
                
                with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                    futures = []
                    for i, cve in enumerate(type3_cves):
                        futures.append(executor.submit(
                            call_llm_for_analysis, 
                            cve, 
                            self.llm
                        ))
                        
                        # 实时进度更新
                        _send_update(f"   - 已提交: {cve.get('VulnerabilityID')} ({i+1}/{len(type3_cves)})")
                        
                        if i < len(type3_cves) - 1:  # 最后一个不需要sleep
                            time.sleep(request_interval)
                    
                    # 处理结果
                    success_count = 0
                    for future in as_completed(futures):
                        result = future.result()
                        type3_analysis_results.append(result)
                        
                        if "error" not in result["analysis"]:
                            success_count += 1
                            status = "✅"
                        else:
                            status = f"⚠️({result['analysis']['error']})"
                        
                        cve_id = result['cve'].get('VulnerabilityID')
                        _send_update(f"   - 完成: {cve_id} {status}")
                
                # 最终统计
                _send_update(f"\n分析完成: {success_count}成功, {len(type3_cves)-success_count}失败")
            _send_update("   - ✅ 全部Type-3漏洞分析完成!")
            
            # --- 步骤 5: 生成报告 ---
            _send_update("\n---\n**步骤 5/5: 生成最终报告和忽略文件...** 📝")
            final_report_data = {
                "type1_cves": type1_cves,
                "type2_cves": type2_cves,
                "type3_results": type3_analysis_results
            }
            final_status = self.reporter.call({'classified_cves': final_report_data})
            
            return f"\n---\n✅ **工作流全部完成!**\n\n```text\n{final_status}\n```"
            
        except Exception as e:
            logging.error(f"工作流执行失败: {e}", exc_info=True)
            return f"\n❌ **工作流执行失败**: {e}"