import os  # 운영체제 관련 작업을 위한 모듈을 불러옵니다.
import time  # 시간 관련 작업을 위한 모듈을 불러옵니다.
import json  # JSON 형식의 데이터를 처리하기 위한 모듈을 불러옵니다.
import glob  # 파일 경로 관련 작업을 위한 모듈을 불러옵니다.
import difflib  # 파일 간의 차이를 비교하기 위한 모듈을 불러옵니다.
import re  # 정규 표현식 관련 작업을 위한 모듈을 불러옵니다.
from env import settings  # 환경 설정 파일에서 설정값을 불러옵니다.
from openai import OpenAI  # OpenAI 관련 작업을 위한 모듈을 불러옵니다.
import tempfile  # 임시 파일 및 디렉토리 작업을 위한 모듈을 불러옵니다.
import instructions  # 별도의 지시사항이 정의된 모듈을 불러옵니다.
import csv  # CSV 형식의 데이터를 처리하기 위한 모듈을 불러옵니다.
import sast_llm  # 특정 목적을 위한 LLM 관련 모듈을 불러옵니다.
from helper_utils import *  # 유틸리티 함수들을 불러옵니다.
from patch_utils import *  # 패치 관련 유틸리티 함수들을 불러옵니다.
from langchain_community.document_loaders import WebBaseLoader  # 웹 데이터를 로드하기 위한 모듈을 불러옵니다.
from langchain.text_splitter import RecursiveCharacterTextSplitter  # 텍스트를 분할하기 위한 모듈을 불러옵니다.
from langchain_community.vectorstores import Chroma  # 벡터 저장소 관련 모듈을 불러옵니다.
from langchain_community.document_loaders import PyPDFLoader  # PDF 데이터를 로드하기 위한 모듈을 불러옵니다.
from langchain_community.document_loaders import OnlinePDFLoader  # 온라인 PDF 데이터를 로드하기 위한 모듈을 불러옵니다.
from langchain_community.document_loaders import PyPDFDirectoryLoader  # PDF 디렉토리 데이터를 로드하기 위한 모듈을 불러옵니다.
from langchain.embeddings.openai import OpenAIEmbeddings  # OpenAI 임베딩 관련 모듈을 불러옵니다.
from langchain.chat_models import ChatOpenAI  # OpenAI 채팅 모델 관련 모듈을 불러옵니다.
from langchain.vectorstores import FAISS  # FAISS 벡터 저장소 관련 모듈을 불러옵니다.
from langchain.chains import LLMChain  # LLM 체인 관련 모듈을 불러옵니다.
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)  # 채팅 프롬프트 관련 모듈을 불러옵니다.


# CWE 번호 리스트를 정의합니다.
CWE_NUMBER = ['CWE-022', 'CWE-078', 'CWE-079', 'CWE-094', 'CWE-400', 'CWE-643', 'CWE-915']
# CodeQL 데이터베이스 경로를 정의합니다.
CODEQL_DB_PATH = 'codeql-db'
# CodeQL QL 파일 경로를 정의합니다.
CODEQL_QL_PATH = '/codeql/codeql-repo/javascript/ql/src/Security/{cwe_number}'
CODEQL_QL_PATH2 = '/codeql/codeql-repo/javascript/ql/src/Security/experiments'
# CodeQL 데이터베이스 생성 명령어를 정의합니다.
CODEQL_CREATE_COMMAND = 'codeql database create --language=javascript --overwrite {db_path} --source-root={src_path}'
# CodeQL 분석 명령어를 정의합니다.
CODEQL_ANALYSIS_COMMAND = 'codeql database analyze {db_path} {ql_path} --format=csv --output={output_path} --threads=16'

# 데이터 리스트를 가져오는 함수입니다.
def get_data_list(cwe_number):
    path_list = []  # 경로 리스트를 초기화합니다.
    path = f'./Dataset/{cwe_number}/'  # CWE 번호에 해당하는 데이터셋 경로를 정의합니다.
    for data in glob.glob(path + '/*'):  # 데이터셋 경로에서 모든 파일을 가져옵니다.
        path_list.append(data)  # 경로 리스트에 파일 경로를 추가합니다.
    
    return path_list  # 경로 리스트를 반환합니다.

# 경로에서 상위 디렉터리 경로를 반환하는 함수입니다.
def get_parent_directory(path):
    return os.path.abspath(os.path.join(path, os.pardir))  # 주어진 경로의 상위 디렉터리 절대 경로를 반환합니다.

# 실험할 데이터셋을 설정하는 함수입니다.
def set_dataset_with_csv():
    os.makedirs(CODEQL_DB_PATH, exist_ok=True)  # 데이터베이스 경로를 생성합니다.
    
    for cwe in CWE_NUMBER:  # 모든 CWE 번호에 대해 반복합니다.
        cwe_path_list = get_data_list(cwe)  # CWE 번호에 해당하는 데이터 리스트를 가져옵니다.
        for path in cwe_path_list:  # 데이터 리스트의 각 경로에 대해 반복합니다.
            filename_path_data = get_js_file_list_without_fixed(path)  # 패치되지 않은 JS 파일 리스트를 가져옵니다.
            for data in filename_path_data:  # 각 JS 파일에 대해 반복합니다.
                db_path = CODEQL_DB_PATH + '/' + data['filename'].split('.')[0]  # 데이터베이스 경로를 설정합니다.
                os.makedirs(db_path, exist_ok=True)  # 데이터베이스 경로를 생성합니다.
                command = CODEQL_CREATE_COMMAND.format(db_path=db_path, src_path=get_parent_directory(data['path']))  # 데이터베이스 생성 명령어를 설정합니다.
                print(command)  # 명령어를 출력합니다.
                os.system(command)  # 명령어를 실행합니다.

                ql_path = CODEQL_QL_PATH.format(cwe_number=cwe)  # QL 파일 경로를 설정합니다.
                command2 = CODEQL_ANALYSIS_COMMAND.format(db_path=db_path, ql_path=ql_path, output_path=get_parent_directory(data['path']) + '/output.csv')  # 분석 명령어를 설정합니다.
                os.system(command2)  # 명령어를 실행합니다.
                print(command2)  # 명령어를 출력합니다.

# URL을 통해서 외부 데이터를 가져오는 함수입니다.
def langchain_data_load_with_url(url: str):
    loader = WebBaseLoader(url)  # 웹 데이터를 로드하기 위한 로더를 설정합니다.
    return loader.load()  # 데이터를 로드하고 반환합니다.

# URL과 클래스 이름을 통해서 외부 데이터를 가져오는 함수입니다.
def langchain_data_load_with_bs4(url: tuple, class_name: tuple):
    loader = WebBaseLoader(
        web_paths=url,
        bs_kwargs=dict(
            parse_only=bs4.SoupStrainer(
                class_=class_name
            )
        ),
    )  # BeautifulSoup을 이용하여 데이터를 로드하기 위한 로더를 설정합니다.
    docs = loader.load()  # 데이터를 로드합니다.
    return docs  # 로드된 데이터를 반환합니다.

# 텍스트 파일을 통해서 데이터를 가져오는 함수입니다.
def langchain_data_load_with_textfile(file_path: str):
    loader = TextLoader(file_path)  # 텍스트 파일을 로드하기 위한 로더를 설정합니다.
    data = loader.load()  # 데이터를 로드합니다.
    return data  # 로드된 데이터를 반환합니다.

# 디렉토리를 통해서 데이터를 가져오는 함수입니다.
def langchain_data_load_with_directory(directory_path: str, glob_opt: str):
    loader = DirectoryLoader(directory_path, glob=glob_opt)  # 디렉토리에서 파일을 로드하기 위한 로더를 설정합니다.
    data = loader.load()  # 데이터를 로드합니다.
    return data  # 로드된 데이터를 반환합니다.

# CSV 파일을 통해서 데이터를 가져오는 함수입니다.
def langchain_data_load_with_csv(csv_path: str):
    loader = CSVLoader(csv_path, encoding='cp949')  # CSV 파일을 로드하기 위한 로더를 설정합니다.
    data = loader.load()  # 데이터를 로드합니다.
    return data  # 로드된 데이터를 반환합니다.

# PDF 파일을 통해서 데이터를 가져오는 함수입니다.
def langchain_data_load_with_pdf(pdf_path: str):
    loader = PyPDFLoader(pdf_path)  # PDF 파일을 로드하기 위한 로더를 설정합니다.
    data = loader.load()  # 데이터를 로드합니다.
    return data  # 로드된 데이터를 반환합니다.

# PDF 파일을 페이지별로 나누어 데이터를 가져오는 함수입니다.
def langchain_data_load_with_pdf(pdf_path: str) -> list:
    loader = PyPDFLoader(pdf_path)  # PDF 파일을 로드하기 위한 로더를 설정합니다.
    data = loader.load_and_split()  # 데이터를 페이지별로 나누어 로드합니다.
    return data  # 로드된 데이터를 반환합니다.

# 온라인 PDF를 통해서 데이터를 가져오는 함수입니다.
def langchain_data_load_with_online_pdf(url: str):
    loader = OnlinePDFLoader(url)  # 온라인 PDF 파일을 로드하기 위한 로더를 설정합니다.
    data = loader.load()  # 데이터를 로드합니다.
    return data[0]  # 첫 번째 데이터를 반환합니다.

# PDF 디렉토리를 통해서 데이터를 가져오는 함수입니다.
def langchain_data_load_with_pdf_directory(directory_path: str, glob_opt: str):
    loader = PyPDFDirectoryLoader(directory_path)  # PDF 디렉토리에서 파일을 로드하기 위한 로더를 설정합니다.
    data = loader.load()  # 데이터를 로드합니다.
    return data  # 로드된 데이터를 반환합니다.

# 데이터를 분할하는 함수입니다.
def langchain_data_split(data: str):
    splitter = RecursiveCharacterTextSplitter(chunk_size=2000, chunk_overlap=200)  # 데이터를 분할하기 위한 스플리터를 설정합니다.
    print(splitter.split_documents(data))  # 분할된 데이터를 출력합니다.

# 취약점 정보에 주석을 추가하는 함수입니다.
def comment_add_to_vulnerabilities(project_path, codeql_csv_path):
    vulnerabilities_dict = parse_codeql_csv(codeql_csv_path)  # CSV 파일에서 취약점 정보를 파싱합니다.
    
    # 같은 파일에 대한 취약점들끼리 모으기 위한 딕셔너리를 초기화합니다.
    vulnerabilities_dict_by_file = dict()
    for vulnerability in vulnerabilities_dict:  # 각 취약점에 대해 반복합니다.
        source_absolute_path = get_full_path(project_path, vulnerability['path'])  # 취약점 파일의 절대 경로를 가져옵니다.
        if source_absolute_path in vulnerabilities_dict_by_file:  # 파일 경로가 이미 딕셔너리에 있는 경우
            vulnerabilities_dict_by_file[source_absolute_path].append(vulnerability)  # 해당 파일에 취약점을 추가합니다.
        else:
            vulnerabilities_dict_by_file[source_absolute_path] = [vulnerability]  # 새로운 파일 경로를 딕셔너리에 추가합니다.
    
    # 파일별로 주석으로 취약점 정보를 추가합니다.
    project_uuid = generate_directory_name()  # 프로젝트 UUID를 생성합니다.
    original_path_copied_path_dict = copy_source_code_files(project_path, project_uuid, vulnerabilities_dict_by_file)  # 소스 코드 파일을 복사합니다.

    for code_path, vulnerabilities in vulnerabilities_dict_by_file.items():  # 파일별로 반복합니다.
        comment_source_code(original_path_copied_path_dict[code_path], vulnerabilities)  # 소스 코드에 주석을 추가합니다.
    
    code_patch_result = dict()  # 코드 패치 결과를 저장할 딕셔너리를 초기화합니다.
    code_patch_result['patched_files'] = dict()  # 패치된 파일 정보를 저장할 딕셔너리를 초기화합니다.
    
    patched_project_save_path = get_comment_code_save_directory(project_path, project_uuid)  # 패치된 프로젝트 저장 경로를 가져옵니다.
    patched_code_save_path = os.path.join(patched_project_save_path, get_relative_path(project_path, code_path))  # 패치된 코드 저장 경로를 설정합니다.
    patched_code_save_path = os.path.abspath(patched_code_save_path)  # 절대 경로로 변환합니다.

    return (vulnerabilities_dict_by_file, patched_code_save_path)  # 취약점 정보와 패치된 코드 경로를 반환합니다.

# RAG 실험을 위한 함수입니다.
def experiment_rag(patch_code, cwe_number):
    pages = langchain_data_load_with_pdf('cwe_v4.12.pdf')  # PDF 파일을 로드합니다.
    embeddings = OpenAIEmbeddings(openai_api_key=settings.LLM_API_KEY['openai'])  # OpenAI 임베딩을 설정합니다.
    db = FAISS.from_documents(pages, embeddings)  # FAISS 데이터베이스를 생성합니다.

    retrieved_pages = db.similarity_search(cwe_number, k=4)  # 유사한 페이지를 검색합니다.
    retrieved_contents = " ".join([p.page_content for p in retrieved_pages])  # 검색된 페이지의 내용을 결합합니다.

    chat = ChatOpenAI(model_name="gpt-4o", temperature=0.7)  # OpenAI 채팅 모델을 설정합니다.

    system_message_prompt = SystemMessagePromptTemplate.from_template(prompt_patch_vulnerabilities)  # 시스템 메시지 프롬프트를 설정합니다.
    human_message_prompt = HumanMessagePromptTemplate.from_template(prompt)  # 인간 메시지 프롬프트를 설정합니다.

    chat_prompt = ChatPromptTemplate.from_messages([system_message_prompt, human_message_prompt])  # 채팅 프롬프트를 설정합니다.
    chain = LLMChain(llm=chat, prompt=chat_prompt)  # LLM 체인을 생성합니다.

    response = chain.run(question=patch_code, docs=retrieved_contents)  # 체인을 실행하여 응답을 얻습니다.
    response = response.replace("\n", "")  # 응답에서 줄바꿈 문자를 제거합니다.

    print(response)  # 응답을 출력합니다.

from tqdm import tqdm  # 진행 상황을 표시하기 위한 모듈을 불러옵니다.

# 시간을 체크하는 함수입니다.
def check_time():
    os.makedirs('rag_results', exist_ok=True)  # RAG 결과 저장 경로를 생성합니다.
    os.makedirs('zero_results', exist_ok=True)  # Zero 결과 저장 경로를 생성합니다.

    for cwe in tqdm(CWE_NUMBER):  # 모든 CWE 번호에 대해 반복합니다.
        cwe_path_list = get_data_list(cwe)  # CWE 번호에 해당하는 데이터 리스트를 가져옵니다.
        for vuln_type in cwe_path_list:  # 데이터 리스트의 각 경로에 대해 반복합니다.
            project_path = vuln_type  # 프로젝트 경로를 설정합니다.
            codeql_csv_path = project_path + '/output.csv'  # CodeQL CSV 경로를 설정합니다.
            print(f'Project Path: {project_path}')  # 프로젝트 경로를 출력합니다.
            print(f'CodeQL CSV Path: {codeql_csv_path}')  # CodeQL CSV 경로를 출력합니다.
            patched_vulnerabilities = sast_llm.patch_vulnerabilities(project_path, codeql_csv_path, code_style_profile=None, zero_shot_cot=False, rag=True)  # 취약점을 패치합니다.
            print(patched_vulnerabilities)  # 패치된 취약점을 출력합니다.

            # 결과를 저장합니다.
            dirname = project_path.split('/')[-1]  # 프로젝트 경로에서 디렉토리 이름을 추출합니다.

            with open(f'rag_results/{dirname}.json', 'w') as f:  # RAG 결과를 저장합니다.
                json.dump(patched_vulnerabilities, f)

            patched_vulnerabilities = sast_llm.patch_vulnerabilities(project_path, codeql_csv_path, code_style_profile=None, zero_shot_cot=False, rag=False)  # Zero 취약점을 패치합니다.
            print(patched_vulnerabilities)  # 패치된 취약점을 출력합니다.

            with open(f'zero_results/{dirname}.json', 'w') as f:  # Zero 결과를 저장합니다.
                json.dump(patched_vulnerabilities, f)

# 시간을 비교하는 함수입니다.
def compare_time():
    total_rag_time = 0  # RAG 총 시간을 초기화합니다.
    total_zero_time = 0  # Zero 총 시간을 초기화합니다.
    rag_count = 0  # RAG 실행 횟수를 초기화합니다.
    zero_count = 0  # Zero 실행 횟수를 초기화합니다.
    faster_rag_count = 0  # RAG가 더 빠른 횟수를 초기화합니다.
    faster_zero_count = 0  # Zero가 더 빠른 횟수를 초기화합니다.
    
    for cwe in tqdm(CWE_NUMBER):  # 모든 CWE 번호에 대해 반복합니다.
        cwe_path_list = get_data_list(cwe)  # CWE 번호에 해당하는 데이터 리스트를 가져옵니다.
        for vuln_type in cwe_path_list:  # 데이터 리스트의 각 경로에 대해 반복합니다.
            project_path = vuln_type  # 프로젝트 경로를 설정합니다.
            dirname = project_path.split('/')[-1]  # 프로젝트 경로에서 디렉토리 이름을 추출합니다.

            try:
                with open(f'rag_results/{dirname}.json', 'r') as f1:  # RAG 결과를 엽니다.
                    rag_vulnerabilities = json.load(f1)
                with open(f'zero_results/{dirname}.json', 'r') as f2:  # Zero 결과를 엽니다.
                    zero_vulnerabilities = json.load(f2)

                rag_patch_time = rag_vulnerabilities['patched_files']['patch_time']  # RAG 패치 시간을 가져옵니다.
                zero_patch_time = zero_vulnerabilities['patched_files']['patch_time']  # Zero 패치 시간을 가져옵니다.

                print(f'[*] {dirname}')  # 디렉토리 이름을 출력합니다.
                print(f'Execution Time Comparison for {dirname}')  # 실행 시간 비교를 출력합니다.
                print('-' * 40)
                print(f'RAG Vulnerabilities Patch Time: {rag_patch_time:.2f} seconds')  # RAG 패치 시간을 출력합니다.
                print(f'Zero Vulnerabilities Patch Time: {zero_patch_time:.2f} seconds')  # Zero 패치 시간을 출력합니다.
                print('-' * 40)
                print(f'Difference in Patch Time: {abs(rag_patch_time - zero_patch_time):.2f} seconds')  # 패치 시간 차이를 출력합니다.

                total_rag_time += rag_patch_time  # 총 RAG 시간을 갱신합니다.
                total_zero_time += zero_patch_time  # 총 Zero 시간을 갱신합니다.
                rag_count += 1  # RAG 실행 횟수를 증가시킵니다.
                zero_count += 1  # Zero 실행 횟수를 증가시킵니다.

                if rag_patch_time < zero_patch_time:  # RAG가 더 빠른 경우
                    faster_rag_count += 1
                elif zero_patch_time < rag_patch_time:  # Zero가 더 빠른 경우
                    faster_zero_count += 1

            except Exception as e:  # 예외 처리
                print(f'Error processing {dirname}: {e}')  # 예외 메시지를 출력합니다.
                continue

    if rag_count > 0 and zero_count > 0:  # 유효한 데이터가 있는 경우
        avg_rag_time = total_rag_time / rag_count  # 평균 RAG 시간을 계산합니다.
        avg_zero_time = total_zero_time / zero_count  # 평균 Zero 시간을 계산합니다.

        print(f'Total RAG Execution Time: {total_rag_time:.2f} seconds')  # 총 RAG 시간을 출력합니다.
        print(f'Total Zero Execution Time: {total_zero_time:.2f} seconds')  # 총 Zero 시간을 출력합니다.
        print(f'Average RAG Execution Time: {avg_rag_time:.2f} seconds')  # 평균 RAG 시간을 출력합니다.
        print(f'Average Zero Execution Time: {avg_zero_time:.2f} seconds')  # 평균 Zero 시간을 출력합니다.
        print(f'RAG was faster {faster_rag_count} times')  # RAG가 더 빠른 횟수를 출력합니다.
        print(f'Zero was faster {faster_zero_count} times')  # Zero가 더 빠른 횟수를 출력합니다.
    else:
        print('No valid data to compare execution times')  # 유효한 데이터가 없는 경우 메시지를 출력합니다.

# JSON 파일을 로드하는 함수입니다.
def load_json(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)  # JSON 파일을 로드하고 반환합니다.

# 파일을 읽는 함수입니다.
def read_file(filepath):
    with open(filepath, 'r') as f:
        return f.read()  # 파일을 읽고 반환합니다.

# 코드를 비교하는 함수입니다.
def compare_code():
    os.makedirs('code_comparison', exist_ok=True)  # 코드 비교 저장 경로를 생성합니다.
    for cwe in tqdm(CWE_NUMBER):  # 모든 CWE 번호에 대해 반복합니다.
        cwe_path_list = get_data_list(cwe)  # CWE 번호에 해당하는 데이터 리스트를 가져옵니다.
        for vuln_type in cwe_path_list:  # 데이터 리스트의 각 경로에 대해 반복합니다.
            project_path = vuln_type  # 프로젝트 경로를 설정합니다.
            dirname = project_path.split('/')[-1]  # 프로젝트 경로에서 디렉토리 이름을 추출합니다.

            with open(f'rag_results/{dirname}.json', 'r') as f1:  # RAG 결과를 엽니다.
                rag_vulnerabilities = json.load(f1)
            with open(f'zero_results/{dirname}.json', 'r') as f2:  # Zero 결과를 엽니다.
                zero_vulnerabilities = json.load(f2)
            
            try:
                print(f'[*] {dirname}')  # 디렉토리 이름을 출력합니다.
                rag_patched_path = rag_vulnerabilities['patched_files'].get(next(iter(rag_vulnerabilities['patched_files'])), None)  # RAG 패치 경로를 가져옵니다.
                zero_patched_path = zero_vulnerabilities['patched_files'].get(next(iter(zero_vulnerabilities['patched_files'])), None)  # Zero 패치 경로를 가져옵니다.
                if rag_patched_path and zero_patched_path:  # RAG와 Zero 패치 경로가 모두 있는 경우
                    rag_patched_content = read_file(rag_patched_path)  # RAG 패치 내용을 읽습니다.
                    zero_patched_content = read_file(zero_patched_path)  # Zero 패치 내용을 읽습니다.
                    with open(f'code_comparison/{dirname}_rag_patched.js', 'w') as f:  # RAG 패치 내용을 저장합니다.
                        f.write(rag_patched_content)
                    with open(f'code_comparison/{dirname}_zero_patched.js', 'w') as f1:  # Zero 패치 내용을 저장합니다.
                        f1.write(zero_patched_content)
                    print(f'Comparing Patched Files for {dirname}')  # 패치된 파일을 비교합니다.
                    
                    print(f'[+] RAG Patched File Path: {rag_patched_path}')  # RAG 패치 파일 경로를 출력합니다.
                    print(rag_patched_content)  # RAG 패치 내용을 출력합니다.
                    print('='*100)
                    print(f'[-] Zero Patched File Path: {zero_patched_path}')  # Zero 패치 파일 경로를 출력합니다.
                    print(zero_patched_content)  # Zero 패치 내용을 출력합니다.
                else:
                    print('Could not find patched files in one or both of the JSON files.')  # 패치된 파일을 찾을 수 없는 경우 메시지를 출력합니다.
                
                print('-'*100)
                print('-'*100)
                print('-'*100)
            except:
                pass

# 데이터를 가져오는 함수입니다.
def get_data():
    path_list = []  # 경로 리스트를 초기화합니다.
    path = f'code_comparison'  # 코드 비교 경로를 설정합니다.
    for data in glob.glob(path + '/*.js'):  # 코드 비교 경로에서 모든 JS 파일을 가져옵니다.
        path_list.append(data)  # 경로 리스트에 파일 경로를 추가합니다.
    
    return path_list  # 경로 리스트를 반환합니다.

# 패치된 파일을 대상으로 다시 취약점 탐지를 수행하는 함수입니다.
def re_codeql_analysis():
    cwe_path_list = get_data()  # 데이터 리스트를 가져옵니다.
    print(cwe_path_list)  # 데이터 리스트를 출력합니다.

    db_path = 'code_comparison/codeql-db'  # 데이터베이스 경로를 설정합니다.
    os.makedirs(db_path, exist_ok=True)  # 데이터베이스 경로를 생성합니다.
    command = CODEQL_CREATE_COMMAND.format(db_path=db_path, src_path='code_comparison')  # 데이터베이스 생성 명령어를 설정합니다.
    print(command)  # 명령어를 출력합니다.
    os.system(command)  # 명령어를 실행합니다.
    command2 = CODEQL_ANALYSIS_COMMAND.format(db_path=db_path, ql_path=CODEQL_QL_PATH2, output_path='./code_comparison/output2.csv')  # 분석 명령어를 설정합니다.
    print(command2)  # 명령어를 출력합니다.
    os.system(command2)  # 명령어를 실행합니다.

# 결과 CSV 파일을 읽는 함수입니다.
def read_output_csv():
    zero = 0  # Zero 결과를 초기화합니다.
    rag = 0  # RAG 결과를 초기화합니다.
    with open('code_comparison/output2.csv', 'r') as f:  # 결과 CSV 파일을 엽니다.
        reader = csv.reader(f)  # CSV 리더를 생성합니다.
        for row in reader:  # 각 행에 대해 반복합니다.
            for i in range(len(row)):  # 각 열에 대해 반복합니다.
                if 'zero_patched' in row[i]:  # Zero 패치 파일이 있는 경우
                    zero += 1
                    break
                elif 'rag_patched' in row[i]:  # RAG 패치 파일이 있는 경우
                    rag += 1
                    break

    print(f'Zero: {zero}')  # Zero 결과를 출력합니다.
    print(f'RAG: {rag}')  # RAG 결과를 출력합니다.                

# 메인 함수입니다.
def main():
    read_output_csv()  # 결과 CSV 파일을 읽습니다.

# 메인 함수가 실행됩니다.
if __name__ == "__main__":
    main()
