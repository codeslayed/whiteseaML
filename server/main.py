from fastapi import FastAPI, Request, HTTPException, File, UploadFile,Response
from pymongo import MongoClient
from pydantic import BaseModel
from config import mycollection, db

app = FastAPI()


@app.post("/upload")
async def upload_file(request: Request):
    # Get the file data as bytes from the request body
    file_data = await request.body()

    # Insert the file data into MongoDB
    result = mycollection.insert_one({'file': file_data})
    return {"message": "File uploaded successfully", "inserted_id": result.inserted_id}

@app.get("/download")
async def download_file():
    file_data = mycollection.find_one()
    if file_data:
        return Response(file_data["file"], media_type="application/octet-stream")
    else:
        return {"message": "File not found"}

@app.get("/")
def home():
    return {"hello world"}