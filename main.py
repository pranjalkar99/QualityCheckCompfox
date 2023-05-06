import datetime as dt
from typing import Dict, List, Optional
import json,os
from google.cloud import storage
from fastapi import BackgroundTasks, FastAPI
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2, OAuth2PasswordRequestForm
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.handlers.sha2_crypt import sha512_crypt as crypto
from pydantic import BaseModel
from rich import inspect, print
from rich.console import Console
from work import get_json,get_first_100
import logging
console = Console()


logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
logging.warning('This will get logged to a file')


# --------------------------------------------------------------------------
# Models and Data
# --------------------------------------------------------------------------
class User(BaseModel):
    username: str
    hashed_password: str


# Create a "database" to hold your data. This is just for example purposes. In
# a real world scenario you would likely connect to a SQL or NoSQL database.
class DataBase(BaseModel):
    user: List[User]

DB = DataBase(
    user=[
        User(username="qa1@1kcompfox.com", hashed_password=crypto.hash("baazigar")),
        User(username="qa2@2kcompfox.com", hashed_password=crypto.hash("compfox")),
        User(username="qa3@3kcompfox.com", hashed_password=crypto.hash("daaskakaam")),
        User(username="qa4@4kcompfox.com", hashed_password=crypto.hash("snoopdog")),
        User(username="qa5@5kcompfox.com", hashed_password=crypto.hash("dicaprio"))
    ]
)


def get_user(username: str) -> User:
    user = [user for user in DB.user if user.username == username]
    if user:
        return user[0]
    return None

# --------------------------------------------------------------------------
# Setup FastAPI
# --------------------------------------------------------------------------
class Settings:
    SECRET_KEY: str = "secret-key"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30  # in mins
    COOKIE_NAME = "access_token"


app = FastAPI()
templates = Jinja2Templates(directory="templates")
settings = Settings()


# get_json()

# --------------------------------------------------------------------------
# Authentication logic
# --------------------------------------------------------------------------
class OAuth2PasswordBearerWithCookie(OAuth2):
    """
    This class is taken directly from FastAPI:
    https://github.com/tiangolo/fastapi/blob/26f725d259c5dbe3654f221e608b14412c6b40da/fastapi/security/oauth2.py#L140-L171
    
    The only change made is that authentication is taken from a cookie
    instead of from the header!
    """
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        # IMPORTANT: this is the line that differs from FastAPI. Here we use 
        # `request.cookies.get(settings.COOKIE_NAME)` instead of 
        # `request.headers.get("Authorization")`
        authorization: str = request.cookies.get(settings.COOKIE_NAME) 
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="token")


def create_access_token(data: Dict) -> str:
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def authenticate_user(username: str, plain_password: str) -> User:
    user = get_user(username)
    if not user:
        return False
    if not crypto.verify(plain_password, user.hashed_password):
        return False
    return user


def decode_token(token: str) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Could not validate credentials."
    )
    token = token.removeprefix("Bearer").strip()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        print(e)
        raise credentials_exception
    
    user = get_user(username)
    return user


def get_current_user_from_token(token: str = Depends(oauth2_scheme)) -> User:
    """
    Get the current user from the cookies in a request.

    Use this function when you want to lock down a route so that only 
    authenticated users can see access the route.
    """
    user = decode_token(token)
    return user


def get_current_user_from_cookie(request: Request) -> User:
    """
    Get the current user from the cookies in a request.
    
    Use this function from inside other routes to get the current user. Good
    for views that should work for both logged in, and not logged in users.
    """
    token = request.cookies.get(settings.COOKIE_NAME)
    user = decode_token(token)
    return user


@app.post("token")
def login_for_access_token(
    response: Response, 
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Dict[str, str]:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"username": user.username})
    
    # Set an HttpOnly cookie in the response. `httponly=True` prevents 
    # JavaScript from reading the cookie.
    response.set_cookie(
        key=settings.COOKIE_NAME, 
        value=f"Bearer {access_token}", 
        httponly=True
    )  
    return {settings.COOKIE_NAME: access_token, "token_type": "bearer"}


# --------------------------------------------------------------------------
# Home Page
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    logging.info("Home Page")
    try:
        user = get_current_user_from_cookie(request)
    except:
        user = None
    context = {
        "user": user,
        "request": request,
    }
    return templates.TemplateResponse("index.html", context)
@app.get("/not_authenticated", response_class=HTMLResponse)
async def not_authenticated(request:Request):
    return templates.TemplateResponse("not_authenticated.html", {"request": request})


# --------------------------------------------------------------------------
# Private Page
# --------------------------------------------------------------------------
# A private page that only logged in users can access.
@app.get("/work", response_class=HTMLResponse)
async def index(request: Request, background_tasks: BackgroundTasks,user: User = Depends(get_current_user_from_token)):
    d={}
    if not user:
        logging.info("No usrr found in work page direct access...")
        context = {"request": request}
        return templates.TemplateResponse("not_authenticated.html",context)
    if user.username == "qa1@1kcompfox.com":
        logging.info("User1 exists...")
        try:
            if(os.path.isfile('db4_data.json')):
                t=open("db4_data.json","r")
                d=json.loads(t.read())
                logging.info("Data-file 1 found in app.")
            else:
                background_tasks.add_task(get_first_100)
                logging.info("Data loading started in background. file 1")

        except:
            logging.error("No db found")
            print("Data Not loaded  or maybe cached in app till now!! i.e the 1k file")
            logging.error("Some error occured while loading db4 inside /work route. for 1k user file")
    if user.username == "qa2@2kcompfox.com":
        try:
            if(os.path.isfile('db4_data_2k.json')):
                t=open("db4_data_2k.json","r")
                d=json.loads(t.read())
                logging.log("Data-file found in app.")
            else:
                background_tasks.add_task(get_second_100)
                logging.log("Data loading started in background.")

        except:
            logging.error("No db found")
            print("Data Not loaded till now!! i.e the 2k file")
            logging.error("Some error occured while loading db4 inside /work route. for 2k user file")
    if user.username == "qa3@3kcompfox.com":
        try:
            if(os.path.isfile('db4_data_3k.json')):
                t=open("db4_data_3k.json","r")
                d=json.loads(t.read())
                logging.log("Data-file found in app.")
            else:
                background_tasks.add_task(get_third_100)
                logging.log("Data loading started in background.")

        except:
            logging.error("No db found")
            print("Data Not loaded till now!! i.e the 3k file")
            logging.error("Some error occured while loading db4 inside /work route. for 3k user file")
    if user.username == "qa3@3kcompfox.com":
        try:
            if(os.path.isfile('db4_data_3k.json')):
                t=open("db4_data_3k.json","r")
                d=json.loads(t.read())
                logging.log("Data-file found in app.")
            else:
                background_tasks.add_task(get_third_100)
                logging.log("Data loading started in background.")

        except:
            logging.error("No db found")
            print("Data Not loaded till now!! i.e the 3k file")
            logging.error("Some error occured while loading db4 inside /work route. for 3k user file")
    if user.username == "qa4@4kcompfox.com":
        try:
            if(os.path.isfile('db4_data_4k.json')):
                t=open("db4_data_4k.json","r")
                d=json.loads(t.read())
                logging.log("Data-file found in app.")
            else:
                background_tasks.add_task(get_fourth_100)
                logging.log("Data loading started in background.")

        except:
            logging.error("No db found")
            print("Data Not loaded till now!! i.e the 2k file")
            logging.error("Some error occured while loading db4 inside /work route. for 2k user file")


    context = {
        "user": user,
        "request": request,
        "data":d,


    }
    return templates.TemplateResponse("work_new.html", context)





# --------------------------------------------------------------------------
# Private Page for each id.. working 
# --------------------------------------------------------------------------
# A private page for each id that only logged in users can access.
if os.path.isfile('db4_data.json'):
    d=open('db4_data.json','r')
    read=json.loads(d.read())


@app.get("/test/{id}",response_class=HTMLResponse)
def test_get(request: Request,id):
    context = {
        "request": request,
        "id":id,
    }
    return templates.TemplateResponse("test.html", context)

# @app.get("/work/{id}/next", response_class=HTMLResponse)
# async def load_work_id_next(request: Request, id: str,user: User = Depends(get_current_user_from_token)):
 



@app.post("/upload-to-gcp")
async def upload_to_gcp(request: Request):
    data = await request.json()
    bucket_name = 'checked_upload'
    storage_client = storage.Client.from_service_account_json('compfox-367313-ad58ca97af3b.json')
    # storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    for html in data['data']:
        blob = bucket.blob(f'html/{html[:10]}.html')
        blob.upload_from_string(html)
    return {'message': 'Data uploaded successfully!'}

@app.get("/work/{id}", response_class=HTMLResponse)
async def load_work_id(request: Request, id: str,user: User = Depends(get_current_user_from_token)):
    obj = read.get(id, None)
    if not obj:
        logging.warning('This is a Warning as obj is not found in db')
        return "Error: Object not found"

    pages = obj['html']
    logging.warning('This is a Warning jsut checking from /work')

    # if request.method == 'POST':
        # global current_page
        # current_page = (current_page + 1) % len(pages)

    context = {
        "request": request,
        "pages": pages,
        "current_page": '0',
        "obj": obj,
        "user":user,
    }
    return templates.TemplateResponse("work_id.html", context)


@app.exception_handler(HTTPException)
async def session_ended_exception_handler(request, exc):
    context = {
        "request": request,
    }
    if exc.detail == "Could not validate credentials.":
        return templates.TemplateResponse("session_end.html",context)
    return templates.TemplateResponse("some_error.html",context)

# --------------------------------------------------------------------------
# Login - GET
# --------------------------------------------------------------------------
@app.get("/auth/login", response_class=HTMLResponse)
def login_get(request: Request):
    context = {
        "request": request,
    }
    return templates.TemplateResponse("login.html", context)


# --------------------------------------------------------------------------
# Login - POST
# --------------------------------------------------------------------------
class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def load_data(self):
        form = await self.request.form()
        self.username = form.get("username")
        self.password = form.get("password")

    async def is_valid(self):
        if not self.username or not (self.username.__contains__("@")):
            self.errors.append("Email is required")
        if not self.password or not len(self.password) >= 4:
            self.errors.append("A valid password is required")
        if not self.errors:
            return True
        return False


@app.post("/auth/login", response_class=HTMLResponse)
async def login_post(request: Request):
    form = LoginForm(request)
    await form.load_data()
    if await form.is_valid():
        try:
            response = RedirectResponse("/", status.HTTP_302_FOUND)
            login_for_access_token(response=response, form_data=form)
            form.__dict__.update(msg="Login Successful!")
            console.log("[green]Login successful!!!!")
            return response
        except HTTPException:
            form.__dict__.update(msg="")
            form.__dict__.get("errors").append("Incorrect Email or Password")
            return templates.TemplateResponse("login.html", form.__dict__)
    return templates.TemplateResponse("login.html", form.__dict__)


# --------------------------------------------------------------------------
# Logout
# --------------------------------------------------------------------------
@app.get("/auth/logout", response_class=HTMLResponse)
def login_get():
    response = RedirectResponse(url="/")
    response.delete_cookie(settings.COOKIE_NAME)
    return response


# async def startup_event():
#     # call your function here
#     await get_first_100()


# @app.on_event("startup")
# async def startup():
#     # create a background task to run the startup event
#     app.add_event_handler("startup", startup_event)