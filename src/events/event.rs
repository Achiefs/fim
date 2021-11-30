pub struct Event<'a> {
  pub id: &'a str,
  //timestamp: String,
  //hostname: String,
  //app: String,
  //pid: u32
}

impl Event<'_> {
  pub fn get_id(&self) -> &str {
    self.id
  }
}