import asyncio
import websockets
import json
import base64

async def test_ncalayer_mock():
    """Тестирование имитации NCALayer"""
    
    try:
        # Подключаемся к mock серверу
        async with websockets.connect('ws://127.0.0.1:13579') as websocket:
            
            # Тест 1: Получение версии
            version_request = {
                "module": "kz.gov.pki.knca.commonUtils",
                "method": "getVersion"
            }
            
            await websocket.send(json.dumps(version_request))
            response = await websocket.recv()
            print("Version response:", json.loads(response))
            
            # Тест 2: Получение активных токенов
            tokens_request = {
                "module": "kz.gov.pki.knca.commonUtils", 
                "method": "getActiveTokens"
            }
            
            await websocket.send(json.dumps(tokens_request))
            response = await websocket.recv()
            print("Tokens response:", json.loads(response))
            
            # Тест 3: Подписание данных
            sign_request = {
                "module": "kz.gov.pki.knca.basics",
                "method": "sign",
                "args": {
                    "format": "cms",
                    "data": base64.b64encode(b"Hello, NCALayer Mock!").decode(),
                    "signingParams": {"detached": True},
                    "signerParams": {},
                    "locale": "ru"
                }
            }
            
            await websocket.send(json.dumps(sign_request))
            response = await websocket.recv()
            sign_response = json.loads(response)
            print("Sign response received")
            
            # Декодируем подпись для просмотра
            if "body" in sign_response and "result" in sign_response["body"]:
                signature = sign_response["body"]["result"]
                decoded = json.loads(base64.b64decode(signature))
                print("Decoded signature:", decoded)
                
    except Exception as e:
        print(f"Connection error: {e}")
        print("Make sure the mock server is running!")

if __name__ == "__main__":
    asyncio.run(test_ncalayer_mock())
