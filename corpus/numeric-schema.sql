-- 숫자형 PII 스키마.
--
-- R2(값 보존이 아닌 집계는 거부) 의 근거는 "마스크값에서 평범한 숫자가
-- 만들어진다" 인데, 정작 **숫자형 PII 컬럼이 코퍼스에 없어 실측하지 못했다**
-- (results/divergence.md 한계 절). 여기서 메운다.
--
-- ★ h5.cust 에 컬럼을 추가하지 않는다. 추가하면 `SELECT *`·전체행 참조 항목의
--   마스킹 컬럼 수가 바뀌어 이미 기록된 모든 숫자(95%/92%/71 vs 70 …)가
--   흔들린다. 별도 테이블로 두면 기존 코퍼스 항목은 한 건도 영향받지 않는다.
--
-- 금융권에서 숫자 자체가 민감정보인 전형: 급여·상여.

DROP TABLE IF EXISTS h5.payroll CASCADE;

CREATE TABLE h5.payroll (
    id            bigserial PRIMARY KEY,
    dept          text          NOT NULL,   -- 비-PII (그룹핑 대조군)
    salary        numeric(12,2) NOT NULL,   -- PII (numeric -> 마스크 0)
    bonus         integer       NOT NULL,   -- PII (int4    -> 마스크 0)
    years_service integer       NOT NULL    -- 비-PII (숫자지만 민감하지 않음)
);

INSERT INTO h5.payroll (dept, salary, bonus, years_service)
SELECT (ARRAY['영업','개발','심사','리스크','준법'])[1 + (i % 5)],
       -- 3200만 ~ 1억 2천만, 부서별로 분포가 다르게
       32000000 + (i % 7) * 4500000 + (i % 13) * 900000,
       1000000 + (i % 11) * 350000,
       1 + (i % 25)
  FROM generate_series(1, 1000) AS i;

INSERT INTO h5.pii_label (relname, attname, kind) VALUES
    ('payroll', 'salary', 'salary'),
    ('payroll', 'bonus',  'bonus')
ON CONFLICT DO NOTHING;

-- 확인: 마스킹 전 실제 분포. 이 값들이 마스킹 후 어떻게 되는지가 측정 대상이다.
SELECT count(*)                       AS rows,
       count(DISTINCT salary)         AS distinct_salary,
       sum(salary)                    AS sum_salary,
       round(avg(salary))             AS avg_salary,
       max(salary)                    AS max_salary,
       min(salary)                    AS min_salary
  FROM h5.payroll;
