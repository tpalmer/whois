class Object
  def blank?
    respond_to?(:empty?) ? empty? : !self
  end unless method_defined?(:blank?)

  def present?
    !blank?
  end unless method_defined?(:present?)
end