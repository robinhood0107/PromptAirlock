# NER 모델·tokenizer·label 설정을 Hugging Face 고정 커밋 URL 에서 받아 빌드 디렉터리 models/ner/ 에 둔다(ADR 0006).
# 받은 파일은 SHA-256 이 맞아야 한다. 모델 파일은 저장소에 넣지 않는다.
# 같은 해시의 파일이 models/phase-2/ 에 있으면 다시 받지 않고 복사해 쓴다.
set(PA_NER_COMMIT 1e75c01e707232401883cf364151bbe2e560c708)
set(PA_NER_CACHE "${PROJECT_SOURCE_DIR}/_deps/ner-${PA_NER_COMMIT}")
set(PA_NER_MODEL_DIR "${CMAKE_BINARY_DIR}/models/ner")

# 빌드 디렉터리 파일 이름|저장소 안 경로|SHA-256
set(PA_NER_FILES
  "model.onnx|onnx/model.onnx|7794bdaa2daaa524d1e7f5e4f80e6b62c6fe3bf36d7a9175f4cd4c011837ddc3"
  "tokenizer.json|tokenizer.json|9bc85a2412ae3694bffac69cb152a9aafd59fd0357e540a343fa9daa62099c38"
  "config.json|config.json|65b1c2e17c4eb6d4f5be29e4374784a03c7b886229af948757e55f3b79444a23")

file(MAKE_DIRECTORY "${PA_NER_CACHE}" "${PA_NER_MODEL_DIR}")
foreach(entry IN LISTS PA_NER_FILES)
  string(REPLACE "|" ";" parts "${entry}")
  list(GET parts 0 name)
  list(GET parts 1 repo_path)
  list(GET parts 2 sha256)
  set(cached "${PA_NER_CACHE}/${name}")
  set(local "${PROJECT_SOURCE_DIR}/models/phase-2/atonlee_koelectra-ko-pii-ner/${repo_path}")
  if(NOT EXISTS "${cached}" AND EXISTS "${local}")
    file(COPY_FILE "${local}" "${cached}")
  endif()
  # 파일이 이미 있고 해시가 맞으면 받지 않는다. 다르면 다시 받고, 그래도 다르면 설정이 실패한다.
  file(DOWNLOAD
    "https://huggingface.co/atonlee/koelectra-ko-pii-ner/resolve/${PA_NER_COMMIT}/${repo_path}"
    "${cached}" EXPECTED_HASH SHA256=${sha256} SHOW_PROGRESS)
  file(COPY_FILE "${cached}" "${PA_NER_MODEL_DIR}/${name}" ONLY_IF_DIFFERENT)
endforeach()
