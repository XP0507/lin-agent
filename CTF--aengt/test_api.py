"""
测试 LLM API 连接
"""
import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 50)
print("环境变量检查:")
print("=" * 50)

api_key = os.getenv("OPENAI_API_KEY")
model = os.getenv("LLM_MODEL")
base_url = os.getenv("LLM_BASE_URL")
provider = os.getenv("LLM_PROVIDER")

print(f"LLM_PROVIDER: {provider}")
print(f"LLM_MODEL: {model}")
print(f"LLM_BASE_URL: {base_url}")
print(f"OPENAI_API_KEY: {api_key[:20]}..." if api_key else "OPENAI_API_KEY: 未设置")

print("\n" + "=" * 50)
print("测试 API 调用:")
print("=" * 50)

try:
    import openai
    
    client = openai.OpenAI(
        api_key=api_key,
        base_url=base_url
    )
    
    print(f"\n正在调用模型: {model}")
    print(f"API 地址: {base_url}")
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "你是一个测试助手"},
            {"role": "user", "content": "请回复: Hello World"}
        ],
        max_tokens=100
    )
    
    print("\n✅ API 调用成功!")
    print(f"响应: {response.choices[0].message.content}")
    
except Exception as e:
    import traceback
    print(f"\n❌ API 调用失败:")
    print(traceback.format_exc())
