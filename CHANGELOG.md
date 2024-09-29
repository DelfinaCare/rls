# CHANGELOG

## v0.2.0 (2024-09-29)

### Feature

* feat: add pypi publish config ([`f45bf07`](https://github.com/DelfinaCare/rls/commit/f45bf075d1ee9fdbc7ef9da845d238da1994c524))

## v0.1.0 (2024-09-29)

### Documentation

* docs: sessioner example update

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt;&#34; ([`223ec46`](https://github.com/DelfinaCare/rls/commit/223ec464404d8652dd21a47f84376e1cba5ba48c))

* docs: update readme

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt;&#34; ([`2cde372`](https://github.com/DelfinaCare/rls/commit/2cde3721db718ff21574f208b2c5134807c8922a))

* docs: update readme

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`e8240b6`](https://github.com/DelfinaCare/rls/commit/e8240b6c0f35ac2b05929870d2e1b758349a3ac5))

### Feature

* feat: add release workflow

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt;&#34; ([`9b51664`](https://github.com/DelfinaCare/rls/commit/9b516643de6b0d90ef8ae53a99b6213b4d4ce693))

* feat: update structure
- add Session class and context getter abstract class
- integrate with alembic and add alembic operations to detect rls policies

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`6bb58c8`](https://github.com/DelfinaCare/rls/commit/6bb58c84402e0360aacb9c1f6552aed1fc6917b6))

* feat: add custom expression support and start testing

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt;&#34; ([`60b9aed`](https://github.com/DelfinaCare/rls/commit/60b9aed5bb407c5c5d225849ec84d726be0c2bae))

* feat: add custom expressions

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`94b076e`](https://github.com/DelfinaCare/rls/commit/94b076efa83abc5ebd1fe1aa3764ce5b857e4aa8))

* feat: add bypassing rls

Co-authored-by: Omar Fahmy &lt;ofahmy1234@gmail.com&gt; ([`5bf4ed3`](https://github.com/DelfinaCare/rls/commit/5bf4ed31394a7fa792cf65c296d8df0ade3b9f8d))

* feat: bind engine to session and make sure the bind is called only once and support multiple sources of comparison with nested fields

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`d47f5d8`](https://github.com/DelfinaCare/rls/commit/d47f5d882c63d4c4672cb14bed84129fdacabc66))

* feat: install once-py package to be used with binding engine

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`4a6e633`](https://github.com/DelfinaCare/rls/commit/4a6e633c216413efc5951a7825ed891f5d0e8174))

* feat: add MIT license

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`08f28f9`](https://github.com/DelfinaCare/rls/commit/08f28f9525bae3bcd87d77ab8492b24fb842fae8))

* feat: add quality test workflow

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`76b820d`](https://github.com/DelfinaCare/rls/commit/76b820d97d93b3f64e35324e224a59e17e4241aa))

* feat: add pre-commit hooks

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`b8747c7`](https://github.com/DelfinaCare/rls/commit/b8747c715e94374fba6f30624cf182157a352194))

* feat: add pyproject.toml and poetry

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`6587edc`](https://github.com/DelfinaCare/rls/commit/6587edcac4c67d08c4ada2c8407f4163fd1eac80))

* feat: update rls api
- change the way expressions are passed in the policy
- set the session variables automatically from header variables

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`ffd3ef6`](https://github.com/DelfinaCare/rls/commit/ffd3ef669cc6997c2848cdc9206be2bc5feb116c))

### Fix

* fix: remove userId from test route in main.py ([`5b91827`](https://github.com/DelfinaCare/rls/commit/5b918276bc0acb329cb3bb3775476b84639373c8))

* fix: change repo name in pipeline workflow

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`a06ff38`](https://github.com/DelfinaCare/rls/commit/a06ff3846391a9518106ab420dd495811827397c))

* fix: mypy static analysis errors

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`981a88d`](https://github.com/DelfinaCare/rls/commit/981a88df2d4d27af608eafc0387b20a8bcca7246))

### Refactor

* refactor: remove req.txt ([`cbf3326`](https://github.com/DelfinaCare/rls/commit/cbf3326fa593bcd636b9c333ac2458d08f29ac6f))

### Test

* test: add tests setup

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`bf0cc9f`](https://github.com/DelfinaCare/rls/commit/bf0cc9f084fa5bfafe3a5d1d3c026f8aa6ba798b))

### Unknown

* doc: add README.md

Co-authored-by: Ghaith Kdimati &lt;gaoia123@gmail.com&gt; ([`3efa5aa`](https://github.com/DelfinaCare/rls/commit/3efa5aa6e3c84b0ea3033e6dfc5e7942c58fd0b4))

* Initial Commit: package structure ([`108750b`](https://github.com/DelfinaCare/rls/commit/108750b13960d5a6eded0eaca00f4d61666b2602))
