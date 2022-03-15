# JWT using Spring Boot & Redis

![banner]()

![badge]()
[![license](https://img.shields.io/github/license/dyparkkk/jwt-spring-security-demo)](https://github.com/dyparkkk/jwt-spring-security-demo/blob/main/LICENSE)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)


> Spring Security와JWT를 사용해서 만든 유저 인증 서비스. 
> 성능과 만료시간 설정 등의 편리함으로 인메모리 데이터 저장소인 redis를 간단하게 사용. 
> 로컬 환경에서 간단하게 사용 가능

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Contributing](#contributing)
- [License](#license)

## 알아두기

```
// build.gradle
implementation 'org.springframework.boot:spring-boot-starter-data-redis'
```
- Spring Data Redis
  - Redis를 JPA Repository처럼 이용가능 하게 인터페이스를 제공해주는 모듈
  - CrudRepository를 지원해서 좀 더 직관적으로 사용 가능

```
implementation group: 'it.ozimov', name: 'embedded-redis', version: '0.7.2'
```
- Embedded Redis
  - 내장 Redis 데몬 -> 로컬 환경에서 추가 데몬 설치없이 사용 가능


## 기본 환경 구성 



### 

## Install

Redis와 H2 저장소 모두 in-memory 환경에서 작동하기 때문에 따로 설치할 것은 없다.

```
```

### Any optional sections

## Usage

```
./gradlew bootRun
```

Note: The `license` badge image link at the top of this file should be updated with the correct `:user` and `:repo`.

### Any optional sections

## API

### Any optional sections

## More optional sections

## Contributing

See [the contributing file](CONTRIBUTING.md)!

PRs accepted.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

### Any optional sections

## License

[MIT © dyparkkk](https://github.com/dyparkkk/jwt-spring-security-demo/blob/main/LICENSE)
