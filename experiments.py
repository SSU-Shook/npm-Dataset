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
from langchain_community.document_loaders import WebBaseLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.document_loaders import OnlinePDFLoader
from langchain_community.document_loaders import PyPDFDirectoryLoader

# def create_database

CWE_NUMBER = ['CWE-022', 'CWE-078', 'CWE-079', 'CWE-094', 'CWE-400', 'CWE-643', 'CWE-915']
CODEQL_DB_PATH = 'codeql-db'
CODEQL_QL_PATH = '/codeql/codeql-repo/javascript/ql/src/Security/{cwe_number}'
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
    splitter = RecursiveCharacterTextSplitter() # RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    # return splitter.split(data)
    print(splitter.split_documents(data))


def main():
    a = langchain_data_load_with_url('https://cwe.mitre.org/data/definitions/78.html')
    print(len(a[0].page_content))
    go = langchain_data_split(a)
    print(go)

    '''
    zero-shot 패치 실험
    1. 데이터셋 csv를 통해서 취약점 줄에 comment를 추가한다.
    2. zero-shot 패치를 진행한다.

    RAG fine-tuning을 이용한 취약점 패치 실험
    1. 데이터셋 csv를 통해서 취약점 줄에 comment를 추가한다.
    2. 해당 취약점에 대한 CWE 외부 정보 langchain 기반 RAG를 진행한다.
    3. 취약점 코드에 패치를 적용한다.

    zeroshot 패치와 RAG fine-tuning 패치의 성능을 비교한다.
    1. 취약점 패치 성공률
    2. ?
    '''

    '''
    변수 선언
    '''
    # codeql csv 파일의 경로
    # codeql_csv_path = input("Enter the path of the CodeQL CSV file: ")
    # codeql_csv_path = os.path.abspath(codeql_csv_path)


    # # 프로젝트의 경로 = codeql csv 상의 경로의 베이스 경로
    # project_path = input("Enter the path of the project: ")
    # project_path = os.path.abspath(project_path)


    # print('-'*50)
    # print(f'CodeQL CSV path: {codeql_csv_path}')
    # print(f'Project path: {project_path}')
    # print('-'*50)

    # # patch_vulnerabilities(project_path, codeql_csv_path, code_style_profile=None, zero_shot_cot=False):
    # # profile_assistant를 사용하여 코딩 컨벤션 프로파일링 결과를 얻는다. (json 문자열 형태)
    # patched_vulnerabilities = sast_llm.patch_vulnerabilities(project_path, codeql_csv_path, code_style_profile=None, zero_shot_cot=False, rag=True)
    
    
    # print(patched_vulnerabilities)


if __name__ == "__main__":
    main()
