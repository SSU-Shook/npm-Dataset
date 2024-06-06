import os
import time
import json
import glob
import difflib
import re
from env import settings
from openai import OpenAI
import tempfile
import instructions
import csv
import sast_llm
from helper_utils import *
from patch_utils import *
from langchain_community.document_loaders import WebBaseLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
# from langchain_openai import OpenAIEmbeddings
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.document_loaders import OnlinePDFLoader
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.chat_models import ChatOpenAI
from langchain.vectorstores import FAISS
from langchain.chains import LLMChain
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)


# def create_database

CWE_NUMBER = ['CWE-022', 'CWE-078', 'CWE-079', 'CWE-094', 'CWE-400', 'CWE-643', 'CWE-915']
CODEQL_DB_PATH = 'codeql-db'
CODEQL_QL_PATH = '/codeql/codeql-repo/javascript/ql/src/Security/{cwe_number}'
CODEQL_QL_PATH2 = '/codeql/codeql-repo/javascript/ql/src/Security/experiments'
# CODEQL_QL_PATH = '/codeql/codeql-repo/javascript/ql/src/Security/CWE-078'
CODEQL_CREATE_COMMAND = 'codeql database create --language=javascript --overwrite {db_path} --source-root={src_path}'
CODEQL_ANALYSIS_COMMAND = 'codeql database analyze {db_path} {ql_path} --format=csv --output={output_path} --threads=16'

def get_data_list(cwe_number):
    '''
    실험할 데이터 리스트를 가져온다.
    '''
    path_list = []
    path = f'./Dataset/{cwe_number}/'
    for data in glob.glob(path + '/*'):
        path_list.append(data)
    
    return path_list

def get_parent_directory(path):
    '''
    경로에서 상위 디렉터리 경로를 반환한다.
    '''
    return os.path.abspath(os.path.join(path, os.pardir))

def set_dataset_with_csv():
    '''
    실험할 데이터셋을 설정한다.
    '''

    os.makedirs(CODEQL_DB_PATH, exist_ok=True)
    
    for cwe in CWE_NUMBER:
        cwe_path_list = get_data_list(cwe)
        for path in cwe_path_list:
            filename_path_data = get_js_file_list_without_fixed(path)
            for data in filename_path_data:
                db_path = CODEQL_DB_PATH + '/' + data['filename'].split('.')[0]
                os.makedirs(db_path, exist_ok=True)
                command = CODEQL_CREATE_COMMAND.format(db_path=db_path, src_path=get_parent_directory(data['path']))
                print(command)
                os.system(command)

                ql_path = CODEQL_QL_PATH.format(cwe_number=cwe)
                command2 = CODEQL_ANALYSIS_COMMAND.format(db_path=db_path, ql_path=ql_path, output_path=get_parent_directory(data['path']) + '/output.csv')
                os.system(command2)   
                print(command2)

# a = langchain_data_load_with_url('https://cwe.mitre.org/data/definitions/78.html')
# print(len(a[0].page_content))
# go = langchain_data_split(a)
# print(go)

def langchain_data_load_with_url(url: str):
    '''
    URL을 통해서 외부 데이터를 가져온다.
    '''
    loader = WebBaseLoader(url)
    
    return loader.load()

def langchain_data_load_with_bs4(url: tuple, class_name: tuple):
    '''
    url: tuple - (url, url, ...)
    class_name: tuple - (class_name, class_name, ...)
    bs4활용, URL을 통해서 외부 데이터를 가져온다.
    '''
    loader = WebBaseLoader(
    web_paths = url,
    bs_kwargs = dict(
        parse_only = bs4.SoupStrainer(
            class_ = class_name
            )
        ),
    )
    docs = loader.load()
    return docs


def langchain_data_load_with_textfile(file_path: str):
    '''
    텍스트 파일을 통해서 데이터를 가져온다.
    '''
    loader = TextLoader(file_path)
    data =  loader.load()
    return data

def langchain_data_load_with_directory(directory_path: str, glob_opt: str):
    '''
    directory_path: str - 파일들을 가져올 디렉토리 경로
    glob_opt: str - glob 옵션 (e.g. '*.txt', '*.csv', ...)
    디렉토리를 통해서 데이터를 가져온다.
    리스트 형태로 반환한다.
    '''
    loader = DirectoryLoader(directory_path, glob=glob_opt)
    data = loader.load()
    return data

def langchain_data_load_with_csv(csv_path: str):
    '''
    csv 파일을 통해서 데이터를 가져온다.
    '''
    loader = CSVLoader(csv_path, encoding='cp949')
    data = loader.load()
    return data

def langchain_data_load_with_pdf(pdf_path: str):
    '''
    pdf 파일을 통해서 데이터를 가져온다.
    리스트 리턴
    '''
    loader = PyPDFLoader(pdf_path)
    data = loader.load()
    return data

def langchain_data_load_with_pdf(pdf_path: str):
    '''
    pdf 파일을 통해서 데이터를 가져온다.
    리스트 리턴
    '''
    loader = PyPDFLoader(pdf_path)
    data = loader.load()
    return data

def langchain_data_load_with_pdf(pdf_path: str) -> list:
    '''
    pdf 파일을 통해서 페이지별로 나누어 데이터를 가져온다.
    리스트 리턴
    '''
    loader = PyPDFLoader(pdf_path)
    data = loader.load_and_split()
    return data

def langchain_data_load_with_online_pdf(url: str):
    '''
    온라인 pdf를 통해서 데이터를 가져온다.
    '''
    loader = OnlinePDFLoader(url)
    data = loader.load()
    return data[0]

def langchain_data_load_with_pdf_directory(directory_path: str, glob_opt: str):
    '''
    pdf 디렉토리를 통해서 데이터를 가져온다.
    '''
    loader = PyPDFDirectoryLoader(directory_path)
    data = loader.load()
    return data


def langchain_data_split(data: str):
    '''
    데이터를 분할한다.
    '''
    splitter = RecursiveCharacterTextSplitter(chunk_size=2000, chunk_overlap=200) # RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    # return splitter.split(data)
    print(splitter.split_documents(data))


def comment_add_to_vulnerabilities(project_path, codeql_csv_path):
    vulnerabilities_dict = parse_codeql_csv(codeql_csv_path)
    
    '''
    같은 파일에 대한 취약점들끼리 모은다.
    {(파일경로, [취약점1, 취약점2, ...]), ...}
    '''
    vulnerabilities_dict_by_file = dict()
    for vulnerability in vulnerabilities_dict:
        source_absolute_path = get_full_path(project_path, vulnerability['path'])
        if source_absolute_path in vulnerabilities_dict_by_file:
            vulnerabilities_dict_by_file[source_absolute_path].append(vulnerability)
        else:
            vulnerabilities_dict_by_file[source_absolute_path] = [vulnerability]
    
    '''
    파일별로 주석으로 취약점 정보를 추가한다.
    이를 위해서는 기존 파일을 복사해서 어딘가에 저장해야 한다.
    어디에 저장할까?
    comment_added_codes 폴더를 추가하자. (해당 폴더는 .gitignore에 추가)

    comment_source_code 함수
    이 함수는 코드 파일의 경로를 입력받아서 취약점 정보를 주석으로 추가한다.

    '''

    project_uuid = generate_directory_name()
    original_path_copied_path_dict = copy_source_code_files(project_path, project_uuid, vulnerabilities_dict_by_file)
    # print(original_path_copied_path_dict)

    for code_path, vulnerabilities in vulnerabilities_dict_by_file.items():
        comment_source_code(original_path_copied_path_dict[code_path], vulnerabilities)
    
    code_patch_result = dict()
    code_patch_result['patched_files'] = dict()
    '''
    파일별로 message를 생성하고 thread를 생성하여 취약점을 패치한다.
    패치된 파일을 다운로드하고, 특정 경로에 patched_원본파일이름 으로 저장한다.
    code_patch_result {'patched_files':{원본경로:패치된파일경로, ...}, 'vulnerabilities_by_file':vulnerabilities_dict_by_file} 반환
    '''
    patched_project_save_path = get_comment_code_save_directory(project_path, project_uuid)

    patched_code_save_path = os.path.join(patched_project_save_path, get_relative_path(project_path, code_path))
    patched_code_save_path = os.path.abspath(patched_code_save_path)
    # for code_path, vulnerabilities in vulnerabilities_dict_by_file.items():
    return (vulnerabilities_dict_by_file, patched_code_save_path)


# def zeroshot_patch_vulnerabilities(project_path, codeql_csv_path):

def experiment_rag(patch_code, cwe_number):
    pages = langchain_data_load_with_pdf('cwe_v4.12.pdf')
    embeddings = OpenAIEmbeddings(openai_api_key = settings.LLM_API_KEY['openai'])
    db = FAISS.from_documents(pages, embeddings)

    retrieved_pages = db.similarity_search(cwe_number, k=4)
    retrieved_contents = " ".join([p.page_content for p in retrieved_pages])

    chat = ChatOpenAI(model_name="gpt-4o", temperature=0.7)

    system_message_prompt = SystemMessagePromptTemplate.from_template(prompt_patch_vulnerabilities)

    human_message_prompt = HumanMessagePromptTemplate.from_template(prompt)

    chat_prompt = ChatPromptTemplate.from_messages(
        [system_message_prompt, human_message_prompt]
    )
    chain = LLMChain(llm=chat, prompt=chat_prompt)

    response = chain.run(question=patch_code, docs=retrieved_contents)
    response = response.replace("\n", "")

    print(response)

from tqdm import tqdm

def check_time():
    os.makedirs('rag_results', exist_ok=True)
    os.makedirs('zero_results', exist_ok=True)

    for cwe in tqdm(CWE_NUMBER):
        cwe_path_list = get_data_list(cwe)
        for vuln_type in cwe_path_list:
            project_path = vuln_type
            codeql_csv_path = project_path + '/output.csv'
            print(f'Project Path: {project_path}')
            print(f'CodeQL CSV Path: {codeql_csv_path}')
            patched_vulnerabilities = sast_llm.patch_vulnerabilities(project_path, codeql_csv_path, code_style_profile=None, zero_shot_cot=False, rag=True)
            print(patched_vulnerabilities) # json

            # # save in results
            dirname = project_path.split('/')[-1]

            with open(f'rag_results/{dirname}.json', 'w') as f:
                json.dump(patched_vulnerabilities, f)

            patched_vulnerabilities = sast_llm.patch_vulnerabilities(project_path, codeql_csv_path, code_style_profile=None, zero_shot_cot=False, rag=False)
            print(patched_vulnerabilities) # json

            with open(f'zero_results/{dirname}.json', 'w') as f:
                json.dump(patched_vulnerabilities, f)

def compare_time():
    total_rag_time = 0
    total_zero_time = 0
    rag_count = 0
    zero_count = 0
    faster_rag_count = 0
    faster_zero_count = 0
    
    for cwe in tqdm(CWE_NUMBER):
        cwe_path_list = get_data_list(cwe)
        for vuln_type in cwe_path_list:
            project_path = vuln_type
            dirname = project_path.split('/')[-1]

            try:
                with open(f'rag_results/{dirname}.json', 'r') as f1:
                    rag_vulnerabilities = json.load(f1)
                with open(f'zero_results/{dirname}.json', 'r') as f2:
                    zero_vulnerabilities = json.load(f2)

                rag_patch_time = rag_vulnerabilities['patched_files']['patch_time']
                zero_patch_time = zero_vulnerabilities['patched_files']['patch_time']

                print(f'[*] {dirname}')
                print(f'Execution Time Comparison for {dirname}')
                print('-' * 40)
                print(f'RAG Vulnerabilities Patch Time: {rag_patch_time:.2f} seconds')
                print(f'Zero Vulnerabilities Patch Time: {zero_patch_time:.2f} seconds')
                print('-' * 40)
                print(f'Difference in Patch Time: {abs(rag_patch_time - zero_patch_time):.2f} seconds')

                total_rag_time += rag_patch_time
                total_zero_time += zero_patch_time
                rag_count += 1
                zero_count += 1

                if rag_patch_time < zero_patch_time:
                    faster_rag_count += 1
                elif zero_patch_time < rag_patch_time:
                    faster_zero_count += 1

            except Exception as e:
                print(f'Error processing {dirname}: {e}')
                continue

    if rag_count > 0 and zero_count > 0:
        avg_rag_time = total_rag_time / rag_count
        avg_zero_time = total_zero_time / zero_count

        print(f'Total RAG Execution Time: {total_rag_time:.2f} seconds')
        print(f'Total Zero Execution Time: {total_zero_time:.2f} seconds')
        print(f'Average RAG Execution Time: {avg_rag_time:.2f} seconds')
        print(f'Average Zero Execution Time: {avg_zero_time:.2f} seconds')
        print(f'RAG was faster {faster_rag_count} times')
        print(f'Zero was faster {faster_zero_count} times')
    else:
        print('No valid data to compare execution times')

def load_json(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def read_file(filepath):
    with open(filepath, 'r') as f:
        return f.read()

def compare_code():
    os.makedirs('code_comparison', exist_ok=True)
    for cwe in tqdm(CWE_NUMBER):
        cwe_path_list = get_data_list(cwe)
        for vuln_type in cwe_path_list:
            project_path = vuln_type
            dirname = project_path.split('/')[-1]

            with open(f'rag_results/{dirname}.json', 'r') as f1:
                rag_vulnerabilities = json.load(f1)
            with open(f'zero_results/{dirname}.json', 'r') as f2:
                zero_vulnerabilities = json.load(f2)
            
            try:
                print(f'[*] {dirname}')
                rag_patched_path = rag_vulnerabilities['patched_files'].get(next(iter(rag_vulnerabilities['patched_files'])), None)
                zero_patched_path = zero_vulnerabilities['patched_files'].get(next(iter(zero_vulnerabilities['patched_files'])), None)
                if rag_patched_path and zero_patched_path:
                    rag_patched_content = read_file(rag_patched_path)
                    zero_patched_content = read_file(zero_patched_path)
                    with open(f'code_comparison/{dirname}_rag_patched.js', 'w') as f:
                        f.write(rag_patched_content)
                    with open(f'code_comparison/{dirname}_zero_patched.js', 'w') as f1:
                        f1.write(zero_patched_content)
                    print(f'Comparing Patched Files for {dirname}')
                    
                    print(f'[+] RAG Patched File Path: {rag_patched_path}')
                    print(rag_patched_content)
                    print('='*100)
                    print(f'[-] Zero Patched File Path: {zero_patched_path}')
                    print(zero_patched_content)
                else:
                    print('Could not find patched files in one or both of the JSON files.')
                
                print('-'*100)
                print('-'*100)
                print('-'*100)
            except:
                pass

def get_data():
    '''
    코드 재탐지시 내부에 있는 실험할 데이터 리스트를 가져온다.
    '''
    path_list = []
    path = f'code_comparison'
    for data in glob.glob(path + '/*.js'):
        path_list.append(data)
    
    return path_list

def re_codeql_analysis():
    '''
    패치된 파일을 대상으로 다시 취약점 탐지 수행
    '''

    # code_comparision
    
    cwe_path_list = get_data()
    print(cwe_path_list)

    db_path = 'code_comparison/codeql-db'
    os.makedirs(db_path, exist_ok=True)
    command = CODEQL_CREATE_COMMAND.format(db_path=db_path, src_path='code_comparison')
    print(command)
    os.system(command)
    command2 = CODEQL_ANALYSIS_COMMAND.format(db_path=db_path, ql_path=CODEQL_QL_PATH2, output_path='./code_comparison/output2.csv')
    print(command2)
    os.system(command2)

def read_output_csv():
    zero = 0
    rag = 0
    with open('code_comparison/output2.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            for i in range(len(row)):
                if 'zero_patched' in row[i]:
                    zero += 1
                    break
                elif 'rag_patched' in row[i]:
                    rag += 1
                    break

    print(f'Zero: {zero}')
    print(f'RAG: {rag}')                

def main():
    read_output_csv()


if __name__ == "__main__":
    main()
