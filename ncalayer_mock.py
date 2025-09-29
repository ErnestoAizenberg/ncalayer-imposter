import asyncio
import websockets
import json
import ssl
import base64
import uuid
from datetime import datetime
from aiohttp import web
import threading
import time
from typing import Dict, Any, Optional


class NCALayerMock:
    def __init__(self):
        self.operations: Dict[str, Dict] = {}
        self.active_connections = set()
        self.storages = {
            "AKKaztokenStore": "KAZTOKEN",
            "AKKZIDCardStore": "IDCard",
            "AKEToken72KStore": "EToken72k",
            "AKEToken5110Store": "EToken5110",
            "AKJaCartaStore": "JaCarta",
            "AKAKEYStore": "AKey",
            "PKCS12": "PKCS12",
            "JKS": "JKS",
        }

    def generate_fake_signature(self, data: str, operation_type: str = "cms") -> str:
        """Генерация фиктивной подписи"""
        fake_data = {
            "type": operation_type,
            "timestamp": datetime.now().isoformat(),
            "data_hash": base64.b64encode(data.encode()[:20].ljust(20, b"0")).decode(),
            "mock_id": str(uuid.uuid4())[:8],
        }
        return base64.b64encode(json.dumps(fake_data).encode()).decode()

    def generate_fake_certificate(self) -> Dict[str, Any]:
        """Генерация фиктивного сертификата"""
        return {
            "subject": {
                "commonName": "TEST USER",
                "surname": "TESTOV",
                "givenName": "TEST",
                "iin": "123456789012",
                "country": "KZ",
                "organization": "TEST ORGANIZATION",
            },
            "issuer": {
                "commonName": "National Certification Center of Kazakhstan",
                "country": "KZ",
            },
            "serialNumber": "1234567890ABCDEF",
            "validFrom": "20230101000000Z",
            "validTo": "20251231235959Z",
            "keyUsage": ["digitalSignature", "nonRepudiation"],
        }

    async def handle_websocket_connection(self, websocket, path):
        """Обработка WebSocket соединений"""
        self.active_connections.add(websocket)
        print(f"WebSocket client connected. Total: {len(self.active_connections)}")

        try:
            async for message in websocket:
                await self.handle_websocket_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            print("WebSocket client disconnected")
        finally:
            self.active_connections.remove(websocket)

    async def handle_websocket_message(self, websocket, message: str):
        """Обработка WebSocket сообщений"""
        try:
            request = json.loads(message)
            print(f"Received request: {request}")

            response = await self.process_request(request)
            await websocket.send(json.dumps(response))
            print(f"Sent response: {response}")

        except json.JSONDecodeError as e:
            error_response = {"code": "400", "message": f"Invalid JSON: {str(e)}"}
            await websocket.send(json.dumps(error_response))
        except Exception as e:
            error_response = {"code": "500", "message": f"Internal error: {str(e)}"}
            await websocket.send(json.dumps(error_response))

    async def process_request(self, request: Dict) -> Dict:
        """Обработка конкретного запроса"""
        module = request.get("module", "")
        method = request.get("method", "")
        args = request.get("args", [])

        # Basics module
        if module == "kz.gov.pki.knca.basics":
            return await self.handle_basics_module(method, request.get("args", {}))

        # CommonUtils module
        elif module == "kz.gov.pki.knca.commonUtils":
            return await self.handle_common_utils_module(method, args)

        # KAZTOKEN mobile extensions
        elif module == "kz.digiflow.mobile.extensions":
            return await self.handle_kaztoken_module(method, args)

        # Default response for unknown modules
        else:
            return {"code": "404", "message": f"Module {module} not found"}

    async def handle_basics_module(self, method: str, args: Dict) -> Dict:
        """Обработка методов модуля basics"""
        if method == "sign":
            return await self.handle_basics_sign(args)
        else:
            return {
                "code": "404",
                "message": f"Method {method} not found in basics module",
            }

    async def handle_basics_sign(self, args: Dict) -> Dict:
        """Обработка подписания через basics"""
        data = args.get("data", "")
        format_type = args.get("format", "cms")
        signing_params = args.get("signingParams", {})

        if isinstance(data, list):
            # Мультиподписание
            results = [
                self.generate_fake_signature(str(item), format_type) for item in data
            ]
            response_data = results
        else:
            # Одиночное подписание
            response_data = self.generate_fake_signature(str(data), format_type)

        return {"status": True, "body": {"result": response_data}}

    async def handle_common_utils_module(self, method: str, args: list) -> Dict:
        """Обработка методов модуля commonUtils"""
        if method == "getVersion":
            return {"result": {"version": "3.0.0.0"}}

        elif method == "getActiveTokens":
            return {"code": "200", "responseObject": list(self.storages.keys())}

        elif method == "getKeyInfo":
            storage_type = args[0] if args else "AKKaztokenStore"
            return {"code": "200", "responseObject": self.generate_fake_certificate()}

        elif method == "createCAdESFromBase64":
            storage_type, key_type, data, attach = args
            signature = self.generate_fake_signature(data, "cms")
            return {"code": "200", "responseObject": signature}

        elif method == "signXml":
            storage_type, key_type, xml_data, xpath1, xpath2 = args
            # Простая имитация XML подписи
            fake_xml_signature = f"""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                    <Reference URI="">
                        <DigestValue>{base64.b64encode(b"fake_digest").decode()}</DigestValue>
                    </Reference>
                </SignedInfo>
                <SignatureValue>{base64.b64encode(b"fake_signature").decode()}</SignatureValue>
            </Signature>
            """
            return {
                "code": "200",
                "responseObject": f"<root>{xml_data}{fake_xml_signature}</root>",
            }

        elif method == "changeLocale":
            locale_id = args[0] if args else "ru"
            return {"code": "200", "responseObject": f"Locale changed to {locale_id}"}

        else:
            return {
                "code": "404",
                "message": f"Method {method} not found in commonUtils module",
            }

    async def handle_kaztoken_module(self, method: str, args: list) -> Dict:
        """Обработка методов KAZTOKEN extensions"""
        if method == "getVersion":
            return {"result": {"version": "2.1.0.0", "type": "KAZTOKEN_DESKTOP"}}
        else:
            return {"code": "404", "message": f"KAZTOKEN method {method} not supported"}

    async def start_websocket_server(self, host: str = "127.0.0.1", port: int = 13579):
        """Запуск WebSocket сервера"""
        print(f"Starting WebSocket server on ws://{host}:{port}")

        # Создаем SSL контекст для wss://
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Для разработки - отключаем проверку сертификатов
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        try:
            server = await websockets.serve(
                self.handle_websocket_connection, host, port, ssl=ssl_context
            )
            print(f"WebSocket server started successfully on wss://{host}:{port}")
            await server.wait_closed()
        except Exception as e:
            print(f"WebSocket server error: {e}")
            # Пробуем без SSL
            server = await websockets.serve(
                self.handle_websocket_connection, host, port
            )
            print(f"WebSocket server started on ws://{host}:{port}")
            await server.wait_closed()


class KAZTOKENHTTPMock:
    """Имитация HTTP API KAZTOKEN"""

    def __init__(self):
        self.operations: Dict[str, Dict] = {}
        self.base_url = "https://127.0.0.1:24680"

    async def handle_http_request(self, request):
        """Обработка HTTP запросов"""
        path = request.path
        method = request.method
        module = request.get("module")

        # CORS headers
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }

        if module == "kz.sapa.eproc.osgi.EprocModule" and method == "version":
            return {
                "result": {
                    "version": "1.4",
                    "name": "SAPA Eproc Module",
                    "compatibility": "NCALayer 3.0",
                }
            }

        if method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        if path == "/":
            return await self.handle_root_request(request, headers)
        else:
            operation_id = path.strip("/")
            return await self.handle_operation_request(request, headers, operation_id)

    async def handle_root_request(self, request, headers):
        """Обработка запроса к корню (инициализация операции)"""
        try:
            if request.content_type == "application/json":
                data = await request.json()
            else:
                data = await request.text()
                data = json.loads(data) if data else {}

            operation_id = str(uuid.uuid4())
            self.operations[operation_id] = {
                "created": datetime.now(),
                "number_of_documents": data.get("numberOfDocuments", 1),
                "base64": data.get("base64", True),
                "encapsulate": data.get("encapsulateContent", False),
                "processed": 0,
                "signatures": [],
            }

            headers["Content-Type"] = "text/plain"
            return web.Response(text=operation_id, status=200, headers=headers)

        except Exception as e:
            return web.Response(text=f"Error: {str(e)}", status=400, headers=headers)

    async def handle_operation_request(self, request, headers, operation_id: str):
        """Обработка запроса к конкретной операции"""
        if operation_id not in self.operations:
            return web.Response(text="Operation not found", status=404, headers=headers)

        operation = self.operations[operation_id]

        try:
            if request.content_type == "application/json":
                data = await request.json()
                document_data = str(data)
            else:
                document_data = await request.text()

            # Генерация фиктивной подписи
            fake_signature = base64.b64encode(
                f"KAZTOKEN_SIGNATURE_{operation_id}_{operation['processed']}".encode()
            ).decode()

            operation["signatures"].append(fake_signature)
            operation["processed"] += 1

            # Если все документы обработаны - очищаем операцию
            if operation["processed"] >= operation["number_of_documents"]:
                del self.operations[operation_id]

            headers["Content-Type"] = "text/plain"
            return web.Response(text=fake_signature, status=200, headers=headers)

        except Exception as e:
            return web.Response(text=f"Error: {str(e)}", status=500, headers=headers)

    async def start_http_server(self, host: str = "127.0.0.1", port: int = 24680):
        """Запуск HTTP сервера"""
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self.handle_http_request)

        # Создаем SSL контекст
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        runner = web.AppRunner(app)
        await runner.setup()

        try:
            site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
            await site.start()
            print(f"HTTP API server started on https://{host}:{port}")

            # Бесконечное ожидание
            await asyncio.Future()

        except Exception as e:
            print(f"HTTPS server error: {e}, trying HTTP...")
            # Пробуем HTTP
            site = web.TCPSite(runner, host, port)
            await site.start()
            print(f"HTTP API server started on http://{host}:{port}")
            await asyncio.Future()


async def main():
    """Основная функция запуска"""
    ncalayer_mock = NCALayerMock()
    kaztoken_mock = KAZTOKENHTTPMock()

    print("Starting NCALayer Mock Servers...")
    print("=" * 50)

    # Запускаем оба сервера параллельно
    await asyncio.gather(
        ncalayer_mock.start_websocket_server(),
        kaztoken_mock.start_http_server(),
        return_exceptions=True,
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down servers...")
    except Exception as e:
        print(f"Fatal error: {e}")
