from pydantic import BaseModel

from pure_backend.deps import ROLE_GENERAL


class UserRegisterReq(BaseModel):
    username: str
    password: str
    id_number: str
    contact: str = ""
    organization_name: str
    organization_code: str | None = None
    role: str = "general"


class LoginReq(BaseModel):
    username: str
    password: str


class PasswordRecoveryRequestReq(BaseModel):
    username: str


class PasswordRecoveryResetReq(BaseModel):
    username: str
    token: str
    new_password: str


class LogoutReq(BaseModel):
    token: str


class WorkflowCreateReq(BaseModel):
    business_number: str
    workflow_code: str
    payload: dict
    idempotency_key: str


class WorkflowDecisionReq(BaseModel):
    decision: str
    comment: str = ""


class MetricIngestReq(BaseModel):
    items: list[dict]


class ExportCreateReq(BaseModel):
    fields: list[str]


class ImportBatchReq(BaseModel):
    items: list[dict]


class SchedulerRunReq(BaseModel):
    should_fail: bool = False


class OrganizationCreateReq(BaseModel):
    name: str
    code: str


class OrganizationJoinReq(BaseModel):
    organization_code: str
    role: str = ROLE_GENERAL


class WorkflowReminderReq(BaseModel):
    before_minutes: int = 120


class AssignTaskReq(BaseModel):
    assign_to_user_id: str
    note: str = ""


class ClaimTaskReq(BaseModel):
    note: str = ""


class WorkflowAllocateReq(BaseModel):
    allocate_to_user_id: str
    department: str = ""
    note: str = ""
