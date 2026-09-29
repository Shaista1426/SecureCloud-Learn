from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, URL, Optional

class CreateCourseForm(FlaskForm):
    title = StringField('Course Title', validators=[DataRequired()])
    description = TextAreaField('Course Description', validators=[DataRequired()])
    image_url = StringField('Course Image URL', validators=[Optional(), URL()])
    textbook_content = TextAreaField('Textbook Content', validators=[Optional()])
    submit = SubmitField('Create Course')

