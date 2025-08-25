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

# --- 1. 从 Qwen-Agent 框架导入依赖 ---
from .base import BaseTool, register_tool
from .base import BaseToolWithFileAccess
from ..llm import BaseChatModel

# --- 2. 全局配置 ---
WORKSPACE = os.path.join(os.getcwd(), 'workspace/doc')
os.makedirs(os.path.join(WORKSPACE, 'reports'), exist_ok=True)
os.makedirs(os.path.join(WORKSPACE, 'debug'), exist_ok=True)


# --- 4. 底层独立工具定义 ---

@register_tool('tk_trivy_scanner')
class TrivyScanner(BaseTool):
    description = "对一个Docker镜像进行Trivy漏洞扫描，并将输出保存为JSON文件。"
    parameters = [{'name': 'image_name', 'type': 'string', 'description': '要扫描的Docker镜像全名', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
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

@register_tool('tk_json_to_csv')
class JsonToCsvConverter(BaseTool):
    description = "将Trivy的JSON报告文件转换为CSV文件。"
    parameters = [{'name': 'json_file_path', 'type': 'string', 'description': 'Trivy扫描产生的JSON文件路径', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
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

@register_tool('tk_cve_classifier')
class CVEClassifier(BaseTool):
    description = "读取两个CVE CSV报告（目标和基础），对漏洞进行分类。"
    parameters = [{'name': 'target_csv_path', 'type': 'string', 'required': True}, {'name': 'base_csv_path', 'type': 'string', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> Dict:
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

@register_tool('tk_cve_reporter')
class CVEReportGenerator(BaseTool):
    description = "根据分类后的CVE列表生成trivyignore文件和建议报告。"
    parameters = [{'name': 'classified_cves', 'type': 'dict', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        try:
            cves_data = self._verify_json_format_args(params).get('classified_cves', {})
            def _write_ignore_file(file_path: Path, ignore_list: List[Dict], header: str):
                if not ignore_list: return 0
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"# {header}\n# Auto-generated by Qwen-Agent\n")
                    f.write("vulnerabilities:\n")
                    for entry in ignore_list:
                        f.write(f"- id: {entry['id']}\n")
                        if entry.get('url'): f.write(f"  url: {entry['url']}\n")
                        f.write(f"  statement: {entry['reason']}\n")
                return len(ignore_list)
            def _write_combined_ignore_file(file_path: Path, ignore_list: List[Dict], header: str):
                if not ignore_list: 
                    return 0
                file_path.parent.mkdir(parents=True, exist_ok=True)
                # 检查文件是否存在，决定是否需要写入header
                write_header = not file_path.exists()
                with open(file_path, 'a', encoding='utf-8') as f:
                    if write_header:
                        f.write(f"# {header}\n# Auto-generated by Qwen-Agent\n")
                        f.write("vulnerabilities:\n")
                        
                    for entry in ignore_list:
                        f.write(f"- id: {entry['id']}\n")
                        if entry.get('url'): 
                            f.write(f"  url: {entry['url']}\n")
                        f.write(f"  statement: {entry['reason']}\n")
                return len(ignore_list)
            
            final_messages = []
            all_ignores = []
            if 'type1_cves' in cves_data or 'type2_cves' in cves_data or 'type3_results' in cves_data:
                type1_ignores = [{'id': c.get('VulnerabilityID', ''), 'url':c.get('PrimaryURL',''), 'reason': "There is currently no recommended version available to fix this vulnerability. We will continue to monitor for updates and apply a fix once it is released."} for c in cves_data.get('type1_cves', [])]
                count1 = _write_ignore_file(Path(WORKSPACE, 'trivyignore-type1.yaml'), type1_ignores, "No fix available.")
                final_messages.append(f"{count1}条Type-1规则 -> trivyignore-type1.yaml")

                all_ignores.extend(type1_ignores)

                type2_ignores = [{'id': c.get('VulnerabilityID', ''), 'url':c.get('PrimaryURL',''), 'reason': "The affected package is not used directly by our application. It comes from the underlying base image. We will continue to monitor and adopt a newer base image if one becomes available that resolves this issue."} for c in cves_data.get('type2_cves', [])]
                count2 = _write_ignore_file(Path(WORKSPACE, 'trivyignore-type2.yaml'), type2_ignores, "Inherited from base.")
                final_messages.append(f"{count2}条Type-2规则 -> trivyignore-type2.yaml")

                all_ignores.extend(type2_ignores)
                
                type3_results = cves_data.get('type3_results', [])
                print(type3_results)
                type3_ignores = [{'id': i.get('cve', {}).get('VulnerabilityID'), 'url': i.get('cve', {}).get('PrimaryURL'), 'reason': f"Type-3 (Analyzed): {i.get('analysis', {}).get('analysis', 'N/A')}"} for i in type3_results if i.get('analysis',{}).get('whether_relevant','N/A') != 'Yes']
                count3 = _write_ignore_file(Path(WORKSPACE, 'trivyignore-type3.yaml'), type3_ignores, "Analyzed by agent.")
                final_messages.append(f"{count3}条Type-3规则 -> trivyignore-type3.yaml")
                
                all_ignores.extend(type3_ignores)
                
                type3_relevant = [{'id': i.get('cve', {}).get('VulnerabilityID'), 'url': i.get('cve', {}).get('PrimaryURL'), 'reason': f"Type-3 (Analyzed): {i.get('analysis', {}).get('analysis', 'N/A')}"} for i in type3_results if i.get('analysis',{}).get('whether_relevant','N/A') == 'Yes']
                count3_relevant = _write_ignore_file(Path(WORKSPACE, 'relevant.yaml'), type3_relevant, "Analyzed by agent.")
                final_messages.append(f"{count3}条Type-3规则 -> relevant.yaml")
                suggestions = [f"[{i.get('cve', {}).get('VulnerabilityID')}/{i.get('cve', {}).get('PkgName')}]: {i.get('analysis', {}).get('suggestion')}" for i in type3_results if i.get('analysis', {}).get('suggestion') and i.get('analysis',{}).get('whether_relevant','N/A') == 'Yes']
                report_path = Path(WORKSPACE, 'reports', 'upgrade_patch_suggestions.txt')
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write("Suggestions from Type-3 Analysis\n" + "="*50 + "\n")
                    if suggestions: f.writelines(f"{s}\n\n" for s in suggestions)
                    else: f.write("No actionable suggestions were generated.\n")
                final_messages.append(f"{len(suggestions)}条建议 -> {report_path.name}")
            if all_ignores:
                combined_count = _write_combined_ignore_file(
                    Path(WORKSPACE, 'trivyignore.yaml'),
                    all_ignores,
                    "Combined ignore rules (Type1 + Type2 + Type3)"
                )
                final_messages.append(f"合并{combined_count}条忽略规则 -> trivyignore.yaml")
            return "报告生成完成。\n- " + "\n- ".join(final_messages)
        except Exception as e:
            return f"报告生成失败: {e}"


# --- 5. 阶段性核心工具定义 ---

@register_tool('cve_initial_workflow')
class InitialWorkflowTool(BaseTool):
    description = "执行CVE扫描和分类的初步工作流。它会自动处理Type-1和Type-2漏洞，并返回一个包含Type-3漏洞列表的JSON对象供后续步骤使用。"
    parameters = [{'name': 'target_image', 'type': 'string', 'required': True}, {'name': 'base_image', 'type': 'string', 'required': True}]
    def __init__(self, cfg: dict = None):
        super().__init__(cfg)
        self.scanner = TrivyScanner()
        self.converter = JsonToCsvConverter()
        self.classifier = CVEClassifier()
        self.reporter = CVEReportGenerator()
    def call(self, params: Union[str, dict], **kwargs) -> str:
        params = self._verify_json_format_args(params)
        target_image, base_image = params['target_image'], params['base_image']
        logging.info("🚀 **阶段一：自动化扫描与分类启动**")
        try:
            target_scan_res = json.loads(self.scanner.call(json.dumps({'image_name': target_image})))
            base_scan_res = json.loads(self.scanner.call(json.dumps({'image_name': base_image})))
            target_csv_res = json.loads(self.converter.call(json.dumps({'json_file_path': target_scan_res['output_path']})))
            base_csv_res = json.loads(self.converter.call(json.dumps({'json_file_path': base_scan_res['output_path']})))
            classification_result = self.classifier.call(json.dumps({'target_csv_path': target_csv_res['output_path'], 'base_csv_path': base_csv_res['output_path']}))
            type1 = classification_result.get('type1_cves', [])
            type2 = classification_result.get('type2_cves', [])
            type3 = classification_result.get('type3_cves_to_analyze', [])
            self.reporter.call(json.dumps({'classified_cves': {'type1_cves': type1, 'type2_cves': type2}}))
            logging.info("  - ✅ Type-1 和 Type-2 的忽略文件已生成。")
            response = {"status": "Phase 1 Complete", "message_for_user": f"初步扫描和分类已完成，共发现 {len(type3)} 个Type-3漏洞。自动进入专家分析阶段...", "type3_cves_data": type3}
            return json.dumps(response, ensure_ascii=False)
        except Exception as e:
            logging.error(f"初步工作流失败: {e}", exc_info=True)
            return json.dumps({"status": "Error", "message": str(e)})

@register_tool('cve_expert_analysis')
class ExpertAnalysisTool(BaseToolWithFileAccess):
    description = "调用一个由“生成者”和“反思者”组成的专家团队，对给定的Type-3漏洞列表进行深度分析，并生成最终报告。"
    parameters = [{'name': 'cve_list', 'type': 'list', 'description': '需要进行深度分析的Type-3漏洞对象列表', 'required': True}]
    def __init__(self, cfg: dict = None, llm: BaseChatModel = None, expert_team=None):
        super().__init__(cfg)
        if not expert_team:
            raise ValueError("ExpertAnalysisTool requires a pre-initialized 'expert_team'.")
        self.llm = llm
        self.expert_team = expert_team # 直接使用传入的专家团队
        self.reporter = CVEReportGenerator()
    def call(self, params: Union[str, dict], **kwargs) -> str:
        files = kwargs.get('files', [])
        logging.info("发现关联文件: %s", str(files))
        for file_path in files:
            if not os.path.exists(file_path):
                logging.warning("文件不存在: %s", file_path)
            else:
                logging.info("文件验证通过: %s", file_path)

        params = self._verify_json_format_args(params)
        cve_list = params['cve_list']
        logging.info(f"🚀 **阶段二：Reflection专家深度分析启动** (分析 {len(cve_list)} 个漏洞)")
        if not cve_list:
            return "专家分析完成：没有需要分析的Type-3漏洞。"
        all_results = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_cve = {executor.submit(self._run_single_reflection_cycle, cve, files): cve for cve in cve_list}
            for i, future in enumerate(as_completed(future_to_cve)):
                cve_id = future_to_cve[future].get('VulnerabilityID')
                logging.info(f"  - ({i+1}/{len(cve_list)}) 完成对 `{cve_id}` 的专家分析...")
                result = future.result()
                all_results.append(result)
        logging.info("  - 正在汇总所有专家分析结果...")
        final_status = self.reporter.call(json.dumps({'classified_cves': {'type3_results': all_results}}))
        return f"✅ **专家分析全部完成!**\n\n{final_status}"
    def _run_single_reflection_cycle(self, cve_data: dict, files:str) -> dict:
        # prompt = f"请深入分析以下CVE，并生成分析报告：\n\n{json.dumps(cve_data, indent=2, ensure_ascii=False)}"
        prompt = f"""
        请严格按以下JSON格式分析CVE漏洞：
        {{
            "risk_level": "高/中/低",
            "whether_relevant" :"是否与目标镜像的使用有关，回答：Yes/No",
            "analysis": "影响分析, 是否与被分析镜像的使用有关，无关的原因，有关的分析",
            "suggestion": "修复建议",
            "workaround": "临时解决方案(如无则留空)"
        }}\n\n
        待分析CVE详情：{json.dumps(cve_data, indent=2, ensure_ascii=False)}
        利用之前传入的Dockerfile文件{files}，根据 id 找到https://avd.aquasec.com/中相关的CVE信息，通过结合{files}，判断是否与这个项目相关。

        """
        response_iterator = self.expert_team.run([{'role': 'user', 'content': prompt}])
        final_response = ""
        for messages in response_iterator:
            if messages and messages[-1]['role'] == 'assistant':
                final_response = messages[-1]['content']
            logging.info(messages[-1]['content'])    
        analysis = {}
        try:
            json_match = re.search(r'\{.*\}', final_response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group(0))
            else:
                analysis = {"analysis": final_response, "suggestion": "未能自动提取结构化建议。"}
        except json.JSONDecodeError:
            analysis = {"analysis": final_response, "suggestion": "最终回复不是有效的JSON格式。"}
        return {"cve": cve_data, "analysis": analysis}