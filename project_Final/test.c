#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_BUFFER_SIZE 2048

char input_binary[100];
char source_code_path[100];
int globalOffset = 0;

// pwntools 라이브러리가 설치되었는지 확인
int is_pwntools_installed() {
    int result = 0;
    FILE* fp = popen("pip show pwntools", "r");
    if (fp != NULL) {
        char buffer[100];
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            if (strstr(buffer, "Name: pwntools") != NULL) {
                result = 1;
                break;
            }
        }
        pclose(fp);
    }
    return result;
}

// Python 3가 설치되었는지 확인
int is_python3_installed() {
    int result = 0;
    FILE* fp = popen("python3 --version", "r");
    if (fp != NULL) {
        char buffer[100];
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            if (strstr(buffer, "Python 3") != NULL) {
                result = 1;
            }
        }
        pclose(fp);
    }
    return result;
}

// 필요한 라이브러리와 Python 버전이 설치되어 있는지 확인
int check_for_ready() {
    int pwntools_installed = is_pwntools_installed();
    int python3_installed = is_python3_installed();

    if (!pwntools_installed || !python3_installed) {
        printf("권장 사항: Python 3와 pwntools 라이브러리를 설치해야 합니다.\n");

        if (!pwntools_installed) {
            printf("pwntools 라이브러리를 설치하세요.\n");
        }

        if (!python3_installed) {
            printf("Python 3를 설치하세요.\n");
        }

        exit(1);
    }

    return 0;
}

// 프로그램의 진행 흐름을 시작하는 함수
void go_go_start() {
    puts("****************************** 스택 시각화 도구 ******************************");

    puts("환영합니다! -- Made By sungjungKim -- 2023/07/11 ");
    puts("이 프로그램은 바이너리 파일을 분석하고 스택 구조를 시각화하는 도구입니다.");
    puts("-- 프로그래밍 언어: C, Python3 --");

    sleep(5);
    puts("****************************** 스택 시각화 도구 ******************************");

    printf("안녕하세요! 본 프로그램을 안내할 BAN입니다.\n");
    printf("프로그램의 진행 흐름은 다음과 같습니다:\n");

    puts("1. 바이너리 파일 경로 입력");
    puts("2. 보호 기법과 함수 목록과 같은 바이너리 파일의 기본 정보 제공");
    puts("3. 스택 구조 시각화");
    puts("4. 익스플로잇 코드 제작");



    char response[2];
    puts("BAN: 바이너리 파일 분석을 시작하시겠습니까? (y/n)");
    printf("입력: ");
    scanf("%1s", response);

    if (response[0] == 'y') {
        analyze_binary();
    } else {
        puts("프로그램을 종료합니다.");
        exit(0);
    }

    sleep(1);

    puts("****************************** 스택 시각화 도구 ******************************");
}

// 바이너리 파일 분석을 위한 경로 입력 함수
void analyze_binary() {
    printf("예시 입력: ./test\n");
    printf("바이너리 파일 경로를 입력하세요 (예: ./test): ");

    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
    fgets(input_binary, sizeof(input_binary), stdin);
    input_binary[strcspn(input_binary, "\n")] = '\0';

    if (input_binary[0] != '.' && input_binary[0] != '/') {
        char temp[100] = "./";
        strcat(temp, input_binary);
        strcpy(input_binary, temp);
    }

    puts("BAB: 바이너리 파일에 대한 기본 정보를 제공합니다.");

    puts("----- 적용된 보호 기법 -----");

    char command[MAX_BUFFER_SIZE];

    snprintf(command, sizeof(command), "checksec --file='%s'", input_binary);

    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        puts("보호 기법 정보를 가져오는 데 실패했습니다.");
        return;
    }

    char checksec_output[MAX_BUFFER_SIZE];
    while (fgets(checksec_output, sizeof(checksec_output), fp)) {
        printf("%s", checksec_output);
    }

    pclose(fp);

    puts("----- 적용된 보호 기법 -----");

    sleep(3);

    puts("이제 스택 구조를 시각화합니다.");
    puts("페이로드 생성에 필요한 오프셋도 제공합니다. <카나리 포함>");

    snprintf(command, sizeof(command), "python3 check_protection.py '%s'", input_binary);
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "명령을 실행하지 못했습니다.\n");
        return;
    }

    printf("Python 스크립트 출력:\n");
    char python_output[MAX_BUFFER_SIZE];
    while (fgets(python_output, sizeof(python_output), fp)) {
        printf("%s", python_output);
        if (strncmp(python_output, "offset :", 8) == 0) {
            char* offset = python_output + 8;
            processOutput(offset);
        }
    }
    pclose(fp);
}

// 출력 값을 처리하는 함수
void processOutput(const char* output) {
    globalOffset = atoi(output);
}

// 소스 코드 파일 경로 입력 함수
void get_source_code_path() {
    printf("소스 코드 파일의 경로를 입력하세요 (예: source_code.c): ");
    scanf("%99s", source_code_path);
}

// 출력을 파일에 저장하는 함수
void save_output_to_file(const char* output_file) {
    FILE* file = fopen(output_file, "w");
    if (file == NULL) {
        fprintf(stderr, "출력 파일을 열지 못했습니다.\n");
        return;
    }

    char command[MAX_BUFFER_SIZE];
    snprintf(command, sizeof(command), "python3 check_protection.py '%s'", input_binary);
    FILE* fp = popen(command, "r");
    if (fp != NULL) {
        char python_output[MAX_BUFFER_SIZE];
        while (fgets(python_output, sizeof(python_output), fp)) {
            fprintf(file, "%s", python_output);
        }
        pclose(fp);
    }

    snprintf(command, sizeof(command), "objdump -d %s", input_binary);
    fp = popen(command, "r");
    if (fp != NULL) {
        fprintf(file, "\n어셈블리 결과:\n");
        char objdump_output[MAX_BUFFER_SIZE];
        while (fgets(objdump_output, sizeof(objdump_output), fp)) {
            fprintf(file, "%s", objdump_output);
        }
        pclose(fp);
    }

    snprintf(command, sizeof(command), "ROPgadget --binary %s --re \"pop\" && ROPgadget --binary %s --re \"ret\"", input_binary, input_binary);
    fp = popen(command, "r");
    if (fp != NULL) {
        fprintf(file, "\nROPgadget 결과:\n");
        char ropgadget_output[MAX_BUFFER_SIZE];
        while (fgets(ropgadget_output, sizeof(ropgadget_output), fp)) {
            fprintf(file, "%s", ropgadget_output);
        }
        pclose(fp);
    }

    snprintf(command, sizeof(command), "ldd -v %s", input_binary);
    fp = popen(command, "r");
    if (fp != NULL) {
        fprintf(file, "\nldd 결과:\n");
        char ldd_output[MAX_BUFFER_SIZE];
        while (fgets(ldd_output, sizeof(ldd_output), fp)) {
            fprintf(file, "%s", ldd_output);
        }
        pclose(fp);
    }

    fp = fopen(source_code_path, "r");
    if (fp != NULL) {
        fprintf(file, "\n---- 소스 코드 ----\n");
        char buffer[MAX_BUFFER_SIZE];
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            fprintf(file, "%s", buffer);
        }
        fprintf(file, "---- 소스 코드 끝 ----\n");
        fclose(fp);
    }

    fclose(file);

    puts("Exploitation에 필요한 정보가 output.txt 파일에 저장되었습니다.");
}

void ignore_pipe_error() {
    signal(SIGPIPE, SIG_IGN);
}


int main() {
    ignore_pipe_error();
    check_for_ready();
    go_go_start();
    get_source_code_path();
    save_output_to_file("output.txt");

    system("python3 gpt.py");

    printf("프로그램을 종료합니다.");

    return 0;
}
