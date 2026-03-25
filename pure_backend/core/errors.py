from fastapi import HTTPException


class AppError(Exception):
    def __init__(self, code: int, msg: str):
        self.code = code
        self.msg = msg
        super().__init__(msg)


def http_error(code: int, msg: str) -> HTTPException:
    return HTTPException(status_code=code, detail={"code": code, "msg": msg})
