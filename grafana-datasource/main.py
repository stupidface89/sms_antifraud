import aiofiles
import uvicorn
from fastapi import FastAPI, Response
from fastapi.staticfiles import StaticFiles


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get('/statistics')
async def get_json():
    async with aiofiles.open("datasource.json") as json_file:
        data = await json_file.read()
        return Response(data)


if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', reload=True)