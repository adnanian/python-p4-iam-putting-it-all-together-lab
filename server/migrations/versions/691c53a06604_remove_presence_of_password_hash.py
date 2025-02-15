"""Remove presence of password hash

Revision ID: 691c53a06604
Revises: 318a0b9b74f7
Create Date: 2024-03-19 14:55:46.999975

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '691c53a06604'
down_revision = '318a0b9b74f7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('_password_hash',
               existing_type=sa.VARCHAR(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('_password_hash',
               existing_type=sa.VARCHAR(),
               nullable=False)

    # ### end Alembic commands ###
