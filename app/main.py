from fastapi import FastAPI

app = FastAPI()

@app.get("/name")
def get_name():
    return "vinoth"