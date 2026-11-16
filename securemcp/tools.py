from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator
from mcp import types

OPERATION = {"type": "string", "minLength": 8, "maxLength": 80, "pattern": "^[a-zA-Z0-9_-]+$"}
ID = {"type": "string", "minLength": 1, "maxLength": 50, "pattern": "^[a-z0-9-]+$"}
DOMAIN = {"type": "string", "minLength": 3, "maxLength": 253}


def string(size: int):
    return {"type": "string", "minLength": 1, "maxLength": size}


def number(maximum: int, minimum: int = 1):
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


@dataclass(frozen=True)
class ToolSpec:
    connector: str
    name: str
    description: str
    risk: str
    scope: str
    props: dict[str, Any]
    required: tuple[str, ...] = ()
    resource: str | None = None

    @property
    def id(self):
        return f"{self.connector}__{self.name}"

    @property
    def write(self):
        return self.risk != "R0"

    def wire(self, public: bool = False) -> types.Tool:
        fields = dict(self.props)
        required = list(self.required)
        if self.write:
            fields["idempotency_key" if public else "operation_id"] = OPERATION
            required.append("idempotency_key" if public else "operation_id")
        return types.Tool(
            name=self.id if public else self.name,
            description=self.description,
            input_schema={
                "type": "object",
                "properties": fields,
                "required": required,
                "additionalProperties": False,
            },
        )


TOOLS = {
    spec.id: spec
    for spec in (
        ToolSpec(
            "crm",
            "list_customers",
            "List assigned synthetic customer cases.",
            "R0",
            "tickets:read",
            {"limit": number(20), "offset": number(100, 0)},
        ),
        ToolSpec(
            "crm",
            "get_customer",
            "Read a synthetic customer case.",
            "R0",
            "tickets:read",
            {"customer_id": ID},
            ("customer_id",),
            "customer_id",
        ),
        ToolSpec(
            "crm",
            "update_customer_status",
            "Set the status of a synthetic customer case.",
            "R1",
            "tickets:write",
            {"customer_id": ID, "status": {"enum": ["open", "pending", "resolved"]}},
            ("customer_id", "status"),
            "customer_id",
        ),
        ToolSpec(
            "crm",
            "update_customer_note",
            "Add a note to a synthetic customer case.",
            "R1",
            "tickets:write",
            {"customer_id": ID, "note": string(500)},
            ("customer_id", "note"),
            "customer_id",
        ),
        ToolSpec(
            "crm",
            "export_customers",
            "Create a bounded synthetic export artifact.",
            "R2",
            "customers:export",
            {"limit": number(20), "destination": DOMAIN},
            ("limit", "destination"),
        ),
        ToolSpec(
            "crm",
            "delete_customer",
            "Delete a synthetic customer case.",
            "R3",
            "customers:delete",
            {"customer_id": ID},
            ("customer_id",),
            "customer_id",
        ),
        ToolSpec(
            "docs",
            "search_documents",
            "Search titles of accessible synthetic documents.",
            "R0",
            "docs:read",
            {"query": string(100), "limit": number(20)},
            ("query",),
        ),
        ToolSpec(
            "docs",
            "read_document",
            "Read an accessible synthetic document.",
            "R0",
            "docs:read",
            {"document_id": ID},
            ("document_id",),
            "document_id",
        ),
        ToolSpec(
            "messages",
            "list_messages",
            "List recent synthetic messages for this tenant.",
            "R0",
            "messages:read",
            {"limit": number(20)},
        ),
        ToolSpec(
            "messages",
            "send_message",
            "Queue a synthetic message for local inspection.",
            "R2",
            "messages:send",
            {"to": string(254), "subject": string(120), "body": string(1600)},
            ("to", "subject", "body"),
        ),
    )
}


def object_schema(fields: dict[str, Any]):
    return {
        "type": "object",
        "properties": fields,
        "required": list(fields),
        "additionalProperties": False,
    }


def array_schema(item: dict[str, Any]):
    return {"type": "array", "items": item, "maxItems": 20}


CUSTOMER_RESULT = object_schema(
    {
        "id": ID,
        "name": string(80),
        "status": string(20),
        "classification": string(20),
        "email": string(120),
        "ssn_demo": string(32),
    }
)
DOCUMENT_FIELDS = {
    "id": ID,
    "title": string(100),
    "classification": string(20),
    "provenance": string(100),
}
MESSAGE_RESULT = object_schema(
    {
        "id": string(50),
        "recipient": string(254),
        "subject": string(120),
        "body": string(1600),
        "state": string(30),
    }
)
OUTPUT_SCHEMAS = {
    "list_customers": {"customers": array_schema(CUSTOMER_RESULT)},
    "get_customer": {"customer": CUSTOMER_RESULT},
    "update_customer_status": {"customer_id": ID, "status": string(20)},
    "update_customer_note": {"note_id": string(36)},
    "export_customers": {
        "artifact_id": string(36),
        "records": number(20, 0),
        "destination": DOMAIN,
    },
    "delete_customer": {"customer_id": ID, "deleted": {"type": "boolean"}},
    "read_document": {"document": object_schema(DOCUMENT_FIELDS | {"body": string(4096)})},
    "search_documents": {"documents": array_schema(object_schema(DOCUMENT_FIELDS))},
    "list_messages": {"messages": array_schema(MESSAGE_RESULT)},
    "send_message": {"message_id": string(36), "state": string(30), "domain": DOMAIN},
}
RESULT_VALIDATORS = {
    name: Draft202012Validator(object_schema(fields)) for name, fields in OUTPUT_SCHEMAS.items()
}
