from fastapi import FastAPI

app = FastAPI(title='dockergenius API')

@app.get('/health')
def health():
    return {'status': 'ok'}
