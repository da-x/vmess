use crate::Error;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum VMState {
    Running,
    Stopped,
}

#[derive(Debug)]
pub enum Expr {
    Substring(String),
    State(VMState),
    All,
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

pub struct MatchInfo<'a> {
    pub vm_state: Option<VMState>,
    pub name: &'a str,
}

impl Expr {
    pub fn parse_cmd(expr: &[String]) -> Result<Self, Error> {
        if expr.len() == 0 {
            return Ok(Expr::All);
        }

        let owner = expr.join(" ");
        match super::expr::topParser::new().parse(owner.as_str()) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::FilterParseError(format!("{}", e))),
        }
    }

    pub fn multiple(mut multiple: Vec<Expr>) -> Self {
        let mut v = multiple.pop().unwrap();
        while let Some(s) = multiple.pop() {
            v = Expr::And(Box::new(s), Box::new(v))
        }

        v
    }

    pub fn match_info(&self, info: &MatchInfo) -> bool {
        match self {
            Expr::Substring(substr) => {
                return info.name.contains(substr);
            }
            Expr::State(state) => {
                return info.vm_state == Some(*state);
            }
            Expr::All => true,
            Expr::Not(a) => !a.match_info(info),
            Expr::And(a, b) => a.match_info(info) && b.match_info(info),
            Expr::Or(a, b) => a.match_info(info) || b.match_info(info),
        }
    }
}
