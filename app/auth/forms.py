from flask_wtf import FlaskForm

from wtforms import (
    StringField,
    PasswordField,
    SelectField,
    SubmitField,
    TextAreaField
)
from wtforms import BooleanField
from wtforms.validators import DataRequired

from wtforms.validators import (
    DataRequired,
    Length,
    Email,
    Regexp,
    EqualTo
)


## ============================================================
# REGISTRATION FORM
# ============================================================

class RegistrationForm(FlaskForm):

    name = StringField(
        'Full Name',
        validators=[
            DataRequired(),
            Length(
                min=2,
                max=50
            )
        ]
    )

    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(
                min=2,
                max=20
            )
        ]
    )

    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email()
        ]
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(
                min=8,
                message="Password must be at least 8 characters long."
            ),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%\*?&]).+$',
                message=(
                    "Password must contain at least one uppercase letter, "
                    "one lowercase letter, one number, and one special character."
                )
            )
        ]
    )

    terms = BooleanField(
        'I agree to the Terms and Conditions',
        validators=[
            DataRequired(
                message="You must agree to the Terms and Conditions."
            )
        ]
    )

    # --------------------------------------------------------
    # CONFIRM PASSWORD
    # --------------------------------------------------------

    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo(
                'password',
                message="Passwords must match."
            )
        ]
    )

    # --------------------------------------------------------
    # SECURITY QUESTION
    # --------------------------------------------------------

    security_question = SelectField(
        'Security Question',
        choices=[
            (
                'What was the name of your first school?',
                'What was the name of your first school?'
            ),
            (
                'What is your favorite food?',
                'What is your favorite food?'
            ),
            (
                'What was the name of your childhood best friend?',
                'What was the name of your childhood best friend?'
            ),
            (
                'What is the name of your favorite place?',
                'What is the name of your favorite place?'
            )
        ],
        validators=[
            DataRequired()
        ]
    )

    # --------------------------------------------------------
    # SECURITY ANSWER
    # --------------------------------------------------------

    security_answer = StringField(
        'Security Answer',
        validators=[
            DataRequired(),
            Length(
                min=2,
                max=100
            )
        ]
    )

    # --------------------------------------------------------
    # ROLE
    # --------------------------------------------------------

    role = SelectField(
        'Role',
        choices=[
            ('student', 'Student'),
            ('instructor', 'Instructor')
        ],
        validators=[
            DataRequired()
        ]
    )

    # --------------------------------------------------------
    # SUBMIT
    # --------------------------------------------------------

    submit = SubmitField(
        'Register'
    )

# ============================================================
# LOGIN FORM
# ============================================================

class LoginForm(FlaskForm):

    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email()
        ]
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired()
        ]
    )

    submit = SubmitField(
        'Login'
    )

    terms = BooleanField(
        'I agree to the Terms and Conditions',
        validators=[
            DataRequired(
                message="You must agree to the Terms and Conditions."
            )
        ]
    )


# ============================================================
# COURSE FORM
# ============================================================

class CourseForm(FlaskForm):

    title = StringField(
        'Title',
        validators=[
            DataRequired()
        ]
    )

    description = TextAreaField(
        'Description',
        validators=[
            DataRequired()
        ]
    )

    video_url = StringField(
        'Video URL'
    )

    image_url = StringField(
        'Image URL'
    )

    submit = SubmitField(
        'Create Course'
    )


# ============================================================
# QUIZ FORM
# ============================================================

class QuizForm(FlaskForm):

    title = StringField(
        'Quiz Title',
        validators=[
            DataRequired()
        ]
    )

    submit = SubmitField(
        'Create Quiz'
    )


# ============================================================
# QUESTION FORM
# ============================================================

class QuestionForm(FlaskForm):

    question_text = TextAreaField(
        'Question',
        validators=[
            DataRequired()
        ]
    )

    option1 = StringField(
        'Option A',
        validators=[
            DataRequired()
        ]
    )

    option2 = StringField(
        'Option B',
        validators=[
            DataRequired()
        ]
    )

    option3 = StringField(
        'Option C',
        validators=[
            DataRequired()
        ]
    )

    option4 = StringField(
        'Option D',
        validators=[
            DataRequired()
        ]
    )

    correct_option = SelectField(
        'Correct Option',
        choices=[
            ('A', 'A'),
            ('B', 'B'),
            ('C', 'C'),
            ('D', 'D')
        ]
    )

    submit = SubmitField(
        'Add Question'
    )