# Filter Rules Usage Guide

Documentation for filtering Flow rules on the web interface.

## Basic Filter Example

```
github
```

Description: Filters Flows that contain `github` in the URL.

## Keywords can be prefixed with a scope

| Scope     | Description                                    |
| --------- | ----------------------------------------------- |
| url       | Request URL                                     |
| method    | HTTP request method (GET / POST etc.)           |
| code      | HTTP response status code                       |
| reqheader | Request header                                  |
| resheader | Response header                                 |
| header    | Request header or response header               |
| reqbody   | Request body                                    |
| resbody   | Response body                                   |
| body      | Request body or response body                   |
| all       | Any of URL / Method / Header / Body             |

## Filter Rule Examples with Scope

### URL Filter

```
url:github
```

Description: Filters Flows that contain `github` in the URL. URL is the default scope.

### Request Method Filter

```
method:get
```

Description: Filters GET requests, case-insensitive.

### Response Status Code Filter

```
code:404
```

Description: Filters Flows with response status code 404.

### Header Filter

```
header:application/json
```

Description: Filters Flows that contain `application/json` in request or response headers.

### Request/Response Body Filter

```
reqbody:token
resbody:token
body:token
```

Description: Filters Flows that contain `token` in the request body, response body, or either body respectively.

### All Filter

```
all:token
```

Description: Filters Flows that contain `token` in any of URL / Header / Body.

### Filter String with Spaces

```
resbody:"hello world"
```

Description: Filters Flows that contain `hello world` in the response body.

## Logical Operators

### or

```
google or baidu
```

Description: Filters Flows that contain `google` or `baidu` in the URL.

### and

```
method:post and body:hello
```

Description: Filters POST requests where the request or response body contains `hello`.

### not

```
not url:github
```

Description: Filters Flows that do not contain `github` in the URL.

### Combined Usage

```
method:get and (url:google or url:baidu) and not resheader:html
```

Description: Filters GET requests where the URL contains `google` or `baidu` and the response header does not contain `html`.
