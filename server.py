from mattermostgithub import app as application

if __name__ == "__main__":
  try:
    import config
  except ImportError:
    from mattermostgithub import config
  application.run(
    host=config.SERVER['address'] or "0.0.0.0",
    port=config.SERVER['port'] or 5000,
    debug=True
  )
