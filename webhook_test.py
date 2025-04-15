import logging, json, uvicorn
from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse
from typing import Any, Dict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("webhook-test-server")

app = FastAPI()

@app.get("/", tags=["健康检查"])
async def root():
    """服务健康检查"""
    return {"status": "online", "service": "webhook-test-server"}

@app.post("/{path:path}", tags=["Webhook"])
async def webhook_handler(
    request: Request,
    path: str,
    payload: Dict[str, Any] = Body(default=None)
):
    """
    接收任何路径的Webhook请求
    
    此端点将接收任何POST请求，记录请求详情并返回接收到的数据
    """
    headers = dict(request.headers)
    query_params = dict(request.query_params)
    full_path = request.url.path
    
    logger.info(f"收到Webhook请求: {full_path}")
    logger.info(f"请求头: {json.dumps(headers, ensure_ascii=False, indent=2)}")
    logger.info(f"查询参数: {json.dumps(query_params, ensure_ascii=False, indent=2)}")
    logger.info(f"请求体: {json.dumps(payload, ensure_ascii=False, indent=2) if payload else '无请求体'}")
    
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "message": "Webhook请求已接收",
            "received_data": {
                "path": full_path,
                "headers": headers,
                "query_params": query_params,
                "payload": payload
            }
        }
    )

def start_server(port: int = 8000):
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Webhook测试")
    parser.add_argument("--port", type=int, default=8000, help="监听端口")
    
    args = parser.parse_args()
    start_server(args.port) 