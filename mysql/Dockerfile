# 공식 최신 MySQL 이미지를 기반으로 시작합니다.
FROM mysql:latest

# 기본 환경 로케일을 UTF-8로 설정합니다.
ENV LANG=ko_KR.UTF-8
ENV LANGUAGE=ko_KR.UTF-8
ENV LC_ALL=ko_KR.UTF-8

# Oracle Linux (RPM 기반)에서 한국어 로케일 지원 패키지를 설치합니다.
# 패키지 매니저로 apt-get 대신 microdnf 를 사용합니다.
RUN microdnf install -y glibc-langpack-ko && microdnf clean all

# 2단계에서 만든 우리만의 설정 파일(custom.cnf)을
# 컨테이너 안의 MySQL 설정 폴더(/etc/mysql/conf.d/)로 복사합니다.
COPY custom.cnf /etc/mysql/conf.d/