from setuptools import setup

setup(
    name="prompt-safety-guard",
    version="1.0.0",
    description="Multi-layer defensive system against LLM prompt attacks",
    author="Aprameya Kannan",
    license="Apache License 2.0",
    py_modules=["prompt_safety_guard"],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
)
