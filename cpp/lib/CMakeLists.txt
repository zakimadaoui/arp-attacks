include(FetchContent)

FetchContent_Declare(
  pcapplusplus
  GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
  GIT_TAG        v25.05
)

FetchContent_MakeAvailable(pcapplusplus)
