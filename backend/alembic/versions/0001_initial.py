"""initial client integrity schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-27
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(36), nullable=False, unique=True, index=True),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("fingerprint_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("trust_score", sa.Float(), nullable=False, server_default="70"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "fingerprints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.device_id"), nullable=False, index=True),
        sa.Column("fingerprint_hash", sa.String(64), nullable=False),
        sa.Column("raw_fingerprint", sa.JSON(), nullable=False),
        sa.Column("drift_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "requests_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(36), nullable=True, index=True),
        sa.Column("ip_address", sa.String(64), nullable=False, index=True),
        sa.Column("method", sa.String(12), nullable=False),
        sa.Column("path", sa.String(255), nullable=False),
        sa.Column("headers", sa.JSON(), nullable=False),
        sa.Column("body_hash", sa.String(64), nullable=False),
        sa.Column("signature_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reason", sa.String(512), nullable=False, server_default=""),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), index=True),
    )
    op.create_table(
        "decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("request_id", sa.Integer(), sa.ForeignKey("requests_log.id"), nullable=True, index=True),
        sa.Column("device_id", sa.String(36), nullable=True, index=True),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), index=True),
    )
    op.create_table(
        "rate_limits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(36), nullable=True, index=True),
        sa.Column("ip_address", sa.String(64), nullable=False, index=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("burst_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("rate_limits")
    op.drop_table("decisions")
    op.drop_table("requests_log")
    op.drop_table("fingerprints")
    op.drop_table("devices")
