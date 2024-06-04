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

# def set_dataset_with_csv()

def main():

    os.makedirs(CODEQL_DB_PATH, exist_ok=True)

    # cwe = 'CWE-022'
    
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
