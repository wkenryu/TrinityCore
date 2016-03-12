FOR %%P IN (proto\*.proto) DO (
  protoc.exe --plugin=protoc-gen-bnet=build\Debug\protoc-gen-bnet.exe --bnet_out=buildproto -Iproto %%P
)
