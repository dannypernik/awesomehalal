"""remove category string from item table

Revision ID: 93192a89c483
Revises: 210e2247fb97
Create Date: 2023-07-12 01:44:09.854217

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '93192a89c483'
down_revision = '210e2247fb97'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item', schema=None) as batch_op:
        batch_op.drop_column('category')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item', schema=None) as batch_op:
        batch_op.add_column(sa.Column('category', sa.VARCHAR(length=64), nullable=True))

    # ### end Alembic commands ###
