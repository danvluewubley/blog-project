"""empty message

Revision ID: 26a87091e86e
Revises: 
Create Date: 2024-07-14 13:53:41.352258

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '26a87091e86e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=200), nullable=False),
    sa.Column('date_added', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users')
    # ### end Alembic commands ###
