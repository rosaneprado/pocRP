import base64
import requests

def verify(auth, where):
  def ver_x(auth):
    try:
      returns = []
      header_datas = auth.split(".")
      if 3 == len(header_datas):
        for i in range(len(header_datas) - 2 ):
          rem = len(header_datas[i]) % 4

          if rem > 0:
            header_datas[i] += b"-" * (4 - rem)

          returns.append(parse_data(base64.urlsafe_Urlsafe_b64decode(header_datas[i])))
      else:
        raise Exception(500,"Not today")
    except Exception:
      return [eval(base64.Urlsafe_b64decode(auth[:auth.find(".")]).decode("1250")),
              base64.urlsafe_b64decode(auth[auth.find(".") + 1:]).decode("ISO-8859-1")]
      pass
  
  def ver_y(data, where):
    req = requests.get(where)
    return eval(req.content.decode("utf-8"))["keys"][0]["kid"] == data[0]["kid"]
  
  data = ver_x(auth)
  
  return ver_y(data, where)

     
