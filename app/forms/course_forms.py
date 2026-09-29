from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired

class CreateCourseForm(FlaskForm):
    title = StringField("Course Title", validators=[DataRequired()])
    description = TextAreaField("Course Description", validators=[DataRequired()])
    submit = SubmitField("Create Course")
